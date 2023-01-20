#!/usr/bin/env python3
# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import argparse
import configparser
import logging
import sys
import warnings

from typing import List
from typing import Dict
from typing import Iterable
from typing import Optional
from typing import Set
from typing import Union

from galaxy_parser import galaxy

try:
    import pymisp
except ImportError as ie:
    print(f"'{__file__}' requires 'pymisp'")
    raise


# Configure the loggers
logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    level=logging.INFO,
)

# Galaxies whose clusters have a suffix-based identity
SUFFIX_BASED_GALAXIES = frozenset(
    [
        "mitre-attack-pattern",  # MITRE techniques can be renamed, but the technique id remains
    ]
)


def is_tag_stale__by_suffix(instance_tag: str, tag: str, separator: Optional[str] = None) -> bool:
    """Return whether the instance tag is stale by looking at the suffix (after separator)."""
    if instance_tag == tag:
        return False
    if not separator:
        separator = " - "
    return instance_tag.split(separator)[-1] == tag.split(separator)[-1]


def is_tag_stale__by_synonym(instance_tag: str, tag: str, synonyms: Dict[str, Set[str]]) -> bool:
    """Return whether the instance tag is stale by checking if it is a synonym now."""
    if instance_tag == tag:
        return False
    return instance_tag in synonyms[tag]


def create_cluster_tag(galaxy_prefix: str, value: str) -> str:
    """Create a galaxy cluster tag given the galaxy prefix and the tag value."""
    return f'{galaxy_prefix}="{value}"'


def get_tag_synonyms(galaxy_values: Iterable[Dict], galaxy_prefix: str) -> Dict[str, Set[str]]:
    """Return all synonyms that the galaxy allows."""
    tag_synonyms = {}
    for entry in galaxy_values:
        cluster_tag = create_cluster_tag(galaxy_prefix, entry["value"])
        synonyms = entry.get("meta", {}).get("synonyms", [])
        tag_synonyms[cluster_tag] = {create_cluster_tag(galaxy_prefix, x) for x in synonyms}
    return tag_synonyms


def get_galaxy_names_from_tag_names(tag_names: Iterable[str]) -> List[str]:
    """Return all galaxy names from the provided tag names."""
    tag_galaxy_names = set([])
    galaxy_type_to_name = {v: k for k, v in galaxy.BaseGalaxyManager.GALAXY_NAME_TO_TYPE.items()}
    for tag_name in tag_names:
        try:
            tag_category, tag_galaxy = tag_name.split("=")[0].split(":")
            if tag_category == "misp-galaxy" and tag_galaxy in galaxy_type_to_name:
                tag_galaxy_names.add(galaxy_type_to_name[tag_galaxy])
        except (IndexError, ValueError):
            continue
    return sorted(tag_galaxy_names)


def get_or_create_tag_object(misp: pymisp.PyMISP, tag: str) -> pymisp.MISPTag:
    """Get or create a tag object."""
    results = misp.search_tags(tag, pythonify=True)
    if results:
        tag_object = results[0]
    else:
        tag_object = pymisp.MISPTag()
        tag_object.from_dict(name=tag)
    return tag_object


def search_and_replace_tag(
    misp: pymisp.PyMISP,
    entity: Union[pymisp.MISPAttribute, pymisp.MISPEvent],
    old_tag: str,
    new_tag: str,
) -> None:
    """Given an entity, replace old tag with new tag."""
    tag_by_name = {x.name: x for x in entity.tags}
    # If the entity does not have any old tags, exit
    if old_tag not in tag_by_name:
        return
    # If the entity does not have any new tag, tag it
    if new_tag not in tag_by_name:
        misp.tag(entity, get_or_create_tag_object(misp, new_tag))
    # Remove from the entity any old tag
    misp.untag(entity, tag_by_name[old_tag])


# pylint:disable=W1203
def main() -> int:
    """Script to replace stale cluster tags."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config-file",
        dest="config_file",
        default="./data/config.ini",
        type=str,
        help="read config from here",
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        dest="dry_run",
        default=False,
        action="store_true",
        help="whether to be a dry run",
    )
    args = parser.parse_args()
    conf = configparser.ConfigParser()
    conf.read(args.config_file)

    # Load MISP
    logger = logging.getLogger(__name__)
    verify_ssl = conf.getboolean("misp", "verify_ssl", fallback=False)
    if not verify_ssl:
        warnings.filterwarnings("ignore", message="Unverified HTTPS request")
    misp = pymisp.PyMISP(
        url=conf.get("misp", "url"),
        key=conf.get("misp", "key"),
        ssl=verify_ssl,
        debug=conf.getboolean("misp", "debug", fallback=False),
    )

    # Load the galaxy manager
    instance_tags = misp.tags(pythonify=True)
    instance_tags_by_name = {x.name: x for x in instance_tags}
    instance_galaxy_names = get_galaxy_names_from_tag_names(instance_tags_by_name.keys())
    galaxy_manager = galaxy.GalaxyManagerMISP(
        misp=misp,
        galaxy_names=instance_galaxy_names,
    )

    # Search for tags to be replaced
    logger.info("Scanning tags")
    old_tag_to_new_tag = {}
    for galaxy_name in galaxy_manager.galaxy_names:
        galaxy_values = galaxy_manager.get_galaxy(galaxy_name)["values"]
        galaxy_prefix = galaxy_manager.get_tag_prefix(galaxy_name)
        galaxy_tags = [create_cluster_tag(galaxy_prefix, x["value"]) for x in galaxy_values]
        galaxy_tag_synonyms = get_tag_synonyms(galaxy_values, galaxy_prefix)
        # iterate over all instance tags and check whether they should be promoted
        for instance_tag in instance_tags_by_name.keys():
            # if the tag from misp is not a galaxy tag, skip it
            if not instance_tag.startswith(f"misp-galaxy:{galaxy_name}"):
                continue
            # if the tag from misp is in the galaxy, we can skip it
            if instance_tag in galaxy_tags:
                continue
            # otherwise let's process all galaxy tags
            for galaxy_tag in galaxy_tags:
                replace = is_tag_stale__by_synonym(instance_tag, galaxy_tag, galaxy_tag_synonyms)
                if not replace and galaxy_name in SUFFIX_BASED_GALAXIES:
                    replace = is_tag_stale__by_suffix(instance_tag, galaxy_tag)
                if replace:
                    logger.info(f"Tag '{instance_tag}' should be replaced with '{galaxy_tag}'")
                    old_tag_to_new_tag[instance_tag] = galaxy_tag

    # Search for tags in existing events
    logger.info("Processing events")
    for idx, (old_tag, new_tag) in enumerate(old_tag_to_new_tag.items(), start=1):
        logger.info(
            f"[{idx}/{len(old_tag_to_new_tag)}] Replacing tag '{old_tag}' with '{new_tag}'"
        )
        events = misp.search(
            controller="events",
            event_tags=old_tag,
            pythonify=True,
        )
        for idx2, event in enumerate(events, start=1):
            logger.info(f"\t[{idx2}/{len(events)}] Processing event '{event.info}'")
            if not args.dry_run:
                search_and_replace_tag(misp, event, old_tag, new_tag)

    # Search for tags in existing attributes
    logger.info("Processing attributes")
    for idx, (old_tag, new_tag) in enumerate(old_tag_to_new_tag.items(), start=1):
        logger.info(
            f"[{idx}/{len(old_tag_to_new_tag)}] Replacing tag '{old_tag}' with '{new_tag}'"
        )
        attributes = misp.search(
            controller="attributes",
            tags=old_tag,
            pythonify=True,
        )
        for idx2, attribute in enumerate(attributes, start=1):
            logger.info(f"\t[{idx2}/{len(attributes)}] Processing attribute '{attribute.uuid}'")
            if not args.dry_run:
                search_and_replace_tag(misp, attribute, old_tag, new_tag)

    return 0


if __name__ == "__main__":
    sys.exit(main())
