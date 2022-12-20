#!/usr/bin/env python3
# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
"""Script to query a MISP galaxy and resolve synonyms."""
import argparse
import os
import sys

import galaxy_parser
from galaxy_parser import galaxy
from galaxy_parser import exceptions


TMP_DIR = "/tmp/"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-q",
        "--query",
        dest="query",
        required=True,
        help="query",
    )
    parser.add_argument(
        "-g",
        "--galaxy-list",
        dest="galaxy_list",
        nargs='+',
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

    # Make sure we can write to a temporary directory
    if os.access(TMP_DIR, os.W_OK):
        cache_directory = TMP_DIR
    else:
        cache_directory = "./"

    # Create galaxy manager and discerners
    galaxy_manager = galaxy.GalaxyManagerOnDemand(
        cache_directory=cache_directory,
        galaxy_names=args.galaxy_list,
        verbose=True,
        force=args.force_download,
    )
    discerners = galaxy_parser.get_discerners(galaxy_manager)

    # Process
    labels = []
    for d in discerners:
        try:
            discernment = d.discern(
                args.query,
                include_partial_matches=args.include_partial_matches,
                hint=args.hint,
            )
            labels.append(discernment.get_tag())
        except exceptions.FailedDiscernment:
            pass
    print(f"Mapping '{args.query}' to: ", labels)

    return 0


if __name__ == "__main__":
    sys.exit(main())
