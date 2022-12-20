# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
from galaxy_parser import discerner
from galaxy_parser import exceptions
from galaxy_parser import galaxy
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional


def get_discerners(
    galaxy_manager: galaxy.BaseGalaxyManagerSubType,
    source: str = None
) -> List[discerner.BaseDiscernerSubType]:
    """Return a list of dynamically created discerners."""
    discerners = []
    for galaxy_name in galaxy_manager.galaxy_names:
        new_type = discerner.BaseDiscerner.create_class(galaxy_name, source or "custom")
        discerners.append(new_type(galaxy_manager))
    return discerners


def get_discerned_tags(
    discerners: Iterable[discerner.BaseDiscernerSubType],
    string: str,
    include_partial_matches: bool = True,
    hint: Optional[str] = None,
) -> List[str]:
    """Get a list of tags from the loaded discerners."""
    labels = []
    if not string:
        return labels
    for d in discerners:
        try:
            discernment = d.discern(string, include_partial_matches, hint)
            labels.append(discernment.get_tag())
        except exceptions.FailedDiscernment:
            continue
    return labels


def get_mitre_technique_mapping(mitre_attack_galaxy_cluster: Dict[str, Any]) -> Dict[str, str]:
    """Get an updated mapping between technique IDs and technique names."""
    return {
        x["value"].split("-")[1].strip(): x["tag_name"]
        for x in mitre_attack_galaxy_cluster["values"]
    }
