# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import ddt
import logging
import unittest

import galaxy_parser
from galaxy_parser import galaxy


GALAXY_DATA = {
    "authors": [
        "Davide Arcuri",
        "Alexandre Dulaunoy",
        "Steffen Enders",
        "Andrea Garavaglia",
        "Andras Iklody",
        "Daniel Plohmann",
        "Christophe Vandeplas",
    ],
    "category": "tool",
    "description": "Malware galaxy cluster based on Malpedia.",
    "name": "Malpedia",
    "source": "Malpedia",
    "type": "malpedia",
    "uuid": "5fc98d08-90a4-498a-ad2e-0edf50ef374e",
    "values": [
        {
            "description": "",
            "meta": {
                "refs": [
                    "https://malpedia.caad.fkie.fraunhofer.de/details/aix.fastcash",
                ],
                "synonyms": [],
                "type": [],
            },
            "uuid": "e8a04177-6a91-46a6-9f63-6a9fac4dfa02",
            "value": "FastCash",
        },
        {
            "description": "",
            "meta": {
                "refs": [
                    "https://malpedia.caad.fkie.fraunhofer.de/details/apk.888_rat",
                    "https://www.welivesecurity.com/2021/09/07/bladehawk-android-espionage-kurdish/",
                ],
                "synonyms": ["888 ROT"],
                "type": [],
            },
            "uuid": "e98ae895-0831-4e10-aad1-593d1c678db1",
            "value": "888 RAT",
        },
        {
            "description": "",
            "meta": {"synonyms": [], "type": []},
            "uuid": "e98ae895-0831-4e10-aad1-593d1c678db2",
            "value": "777 RAT (Win)",
        },
        {
            "description": "",
            "meta": {"synonyms": [], "type": []},
            "uuid": "e98ae895-0831-4e10-aad1-593d1c678db3",
            "value": "777 RAT (ELF)",
        },
    ],
}


@ddt.ddt
class TestDiscernersCustom(unittest.TestCase):
    """Test the discerners."""

    @ddt.data(
        ("888 RAT", "888 RAT"),
        ("888", "888 RAT"),
    )
    def test_discerner(self, args):
        """Test the standard discerner."""
        label, discernment = args
        galaxy_manager = galaxy.GalaxyManagerCustom(
            galaxy_data=GALAXY_DATA,
            galaxy_name=GALAXY_DATA["type"],
        )
        discerner_objects = galaxy_manager.create_discerners()
        discernments = galaxy_parser.get_discernments(discerner_objects, label)
        self.assertEqual(discernments[0].discerned_name, discernment)


@ddt.ddt
class TestDiscernersMalpedia(unittest.TestCase):
    """Test the discerners."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._galaxy_manager = galaxy.GalaxyManagerLocal(
            input_directory="./tests/data/",
            galaxy_names=["malpedia"],
            commit_hash="b787bbe",
        )
        logging.basicConfig(
            format="%(levelname)s: %(message)s",
            level=logging.DEBUG,
        )

    @ddt.data(
        ("888", "888 RAT", True, None),
        ("acbackdoor", "ACBackdoor (ELF)", True, "elf"),
        ("babuk", "Babuk (ELF)", True, "elf"),
        ("blackbasta", "Black Basta", True, "elf"),
        ("blackmatter", "BlackMatter (ELF)", True, "elf"),
        ("blackmatter", "BlackMatter (Windows)", True, "win"),
        ("cronrat", "CronRAT", True, "elf"),
        ("darkside", "DarkSide (ELF)", True, "elf"),
        ("defray", "Defray", True, "elf"),
        ("ech0raix", "QNAPCrypt", True, "elf"),
        ("erebus", "Erebus (ELF)", True, "elf"),
        ("kinsing", "Kinsing", True, "elf"),
        ("lockbit", "LockBit (ELF)", True, "elf"),
        ("merlin", "Merlin", True, "elf"),
        ("redalert", "Red Alert", True, "elf"),
        ("redxor", "RedXOR", True, "elf"),
        ("revil", "REvil (ELF)", True, "elf"),
        ("sysrv", "Sysrv-hello (ELF)", True, "elf"),
        ("teamtnt", "TeamTNT", True, "elf"),
        ("vermilion-strike", "Vermilion Strike (ELF)", True, "elf"),
        ("Venom Loader", "Venom RAT", True, None),
        ("Crimson RAT", "Crimson RAT", True, None),
    )
    def test_discerner__partial(self, args):
        """Test the standard discerner."""
        label, discernment, partial_marches, hint = args
        discerner_objects = self._galaxy_manager.create_discerners()
        discernments = galaxy_parser.get_discernments(
            discerner_objects,
            label,
            include_partial_matches=partial_marches,
            hint=hint,
        )
        self.assertEqual(discernments[0].discerned_name, discernment)


if __name__ == "__main__":
    unittest.main()
