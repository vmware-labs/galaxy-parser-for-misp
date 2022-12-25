#!/usr/bin/env python3
# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import argparse
import sys
import tempfile

from galaxy_parser import exceptions
from galaxy_parser import galaxy


def main():
    """Script to query a MISP galaxy and resolve synonyms."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "query",
        help="the value to query",
    )
    parser.add_argument(
        "-g",
        "--galaxy-list",
        dest="galaxy_list",
        nargs="+",
        default=["mitre-intrusion-set", "mitre-malware", "mitre-tool"],
        help="list of galaxy clusters to query",
    )
    parser.add_argument(
        "-f",
        "--force-download",
        dest="force_download",
        default=False,
        action="store_true",
        help="whether to force download",
    )
    parser.add_argument(
        "-m",
        "--include_partial_matches",
        dest="include_partial_matches",
        default=False,
        action="store_true",
        help="whether the query should allow partial matches",
    )
    parser.add_argument(
        "-i",
        "--hint",
        dest="hint",
        default=None,
        help="specify a hint",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        default=False,
        action="store_true",
        help="whether to be verbose",
    )
    args = parser.parse_args()

    # Create galaxy manager
    galaxy_manager = galaxy.GalaxyManagerOnDemand(
        cache_directory=tempfile.gettempdir(),
        galaxy_names=args.galaxy_list,
        verbose=True,
        force=args.force_download,
    )

    # Process
    labels = []
    for d in galaxy_manager.create_discerners():
        try:
            discernment = d.discern(
                args.query,
                include_partial_matches=args.include_partial_matches,
                hint=args.hint,
            )
            labels.append(discernment.get_tag())
        except exceptions.FailedDiscernment:
            pass

    # Print output
    print(f"Mapping '{args.query}' to: ", labels)

    return 0


if __name__ == "__main__":
    sys.exit(main())
