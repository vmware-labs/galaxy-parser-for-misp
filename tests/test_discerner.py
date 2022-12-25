# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import ddt
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
        "Christophe Vandeplas"
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
                "type": []
            },
            "uuid": "e8a04177-6a91-46a6-9f63-6a9fac4dfa02",
            "value": "FastCash"
        },
        {
            "description": "",
            "meta": {
                "refs": [
                    "https://malpedia.caad.fkie.fraunhofer.de/details/apk.888_rat",
                    "https://www.welivesecurity.com/2021/09/07/bladehawk-android-espionage-kurdish/"
                ],
                "synonyms": ["888 ROT"],
                "type": []
            },
            "uuid": "e98ae895-0831-4e10-aad1-593d1c678db1",
            "value": "888 RAT"
        },
        {
            "description": "",
            "meta": {
                "synonyms": [],
                "type": []
            },
            "uuid": "e98ae895-0831-4e10-aad1-593d1c678db2",
            "value": "777 RAT (Win)"
        },
        {
            "description": "",
            "meta": {
                "synonyms": [],
                "type": []
            },
            "uuid": "e98ae895-0831-4e10-aad1-593d1c678db3",
            "value": "777 RAT (ELF)"
        },
    ],
}


@ddt.ddt
class TestDiscerners(unittest.TestCase):
    """Test the discerners."""

    @ddt.data(
        ("888 RAT", "888 RAT"),
        ("888", "888 RAT"),
        ("888 ROT", "888 RAT"),
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


if __name__ == "__main__":
    unittest.main()
