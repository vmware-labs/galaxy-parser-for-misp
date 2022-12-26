# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import ddt
import json
import mock
import unittest

from galaxy_parser import galaxy


@ddt.ddt
class TestGalaxyManager(unittest.TestCase):
    """Class testing galaxy managers."""

    # this is the object returned by 'get_galaxy' when not receiving python objects
    TEST_GALAXY_DATA = {
        "Galaxy": {
            "type": "malpedia",
        },
        "GalaxyCluster": [],
    }

    # these are the attributes of a partially loaded galaxy object
    TEST_GALAXY_OBJECT_ATTRIBUTE_VALUES = {
        "type": "malpedia",
        "values": [],
    }

    # this is the resulting galaxy loaded in the galaxy manager
    TEST_EXPECTED_GALAXY_DATA = {
        "type": "malpedia",
        "values": [],
    }

    def test_misp(self):
        """Test the manager relying on MISP."""
        galaxy_object_mock = mock.Mock()
        for attr, value in self.TEST_GALAXY_OBJECT_ATTRIBUTE_VALUES.items():
            setattr(galaxy_object_mock, attr, value)
        pymisp_mock = mock.Mock()
        pymisp_mock.galaxies.return_value = [galaxy_object_mock]
        pymisp_mock.get_galaxy.return_value = self.TEST_GALAXY_DATA
        # run
        galaxy_manager = galaxy.GalaxyManagerMISP(
            misp=pymisp_mock,
            galaxy_names=["malpedia"],
        )
        # verify
        pymisp_mock.galaxies.assert_called_once()
        pymisp_mock.get_galaxy.assert_called_once_with(
            galaxy=galaxy_object_mock,
            withCluster=True,
            pythonify=False,
        )
        self.assertCountEqual(galaxy_manager.galaxy_names, ["malpedia"])
        self.assertEqual(galaxy_manager.get_galaxy("malpedia"), self.TEST_EXPECTED_GALAXY_DATA)

    @mock.patch("builtins.open", mock.mock_open(read_data=json.dumps(TEST_EXPECTED_GALAXY_DATA)))
    def test_local(self):
        """Test the local galaxy manager."""
        # run
        galaxy_manager = galaxy.GalaxyManagerLocal(
            input_directory="./",
            galaxy_names=["malpedia"],
            commit_hash=None,
        )
        # verify
        self.assertCountEqual(galaxy_manager.galaxy_names, ["malpedia"])
        self.assertEqual(galaxy_manager.get_galaxy("malpedia"), self.TEST_EXPECTED_GALAXY_DATA)

    @ddt.data(
        (None, "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json"),
        ("345", "https://raw.githubusercontent.com/MISP/misp-galaxy/345/clusters/malpedia.json"),
    )
    @mock.patch("requests.get")
    @mock.patch("shutil.copyfileobj")
    @mock.patch("galaxy_parser.galaxy.GalaxyManagerLocal.__init__")
    @mock.patch("builtins.open", mock.mock_open())
    def test_on_demand(self, args, mock_local, mock_copy, mock_get):
        """Test the local galaxy manager fetching data on demand."""
        commit_hash, final_url = args
        # run
        _ = galaxy.GalaxyManagerOnDemand(
            cache_directory="./",
            galaxy_names=["malpedia"],
            commit_hash=commit_hash,
            verbose=False,
            force=True,
        )
        # verify
        mock_local.assert_called_once_with(
            input_directory="./",
            galaxy_names=["malpedia"],
            commit_hash=commit_hash,
        )
        mock_copy.assert_called_once()
        mock_get.assert_called_once_with(
            final_url,
            stream=mock.ANY,
            allow_redirects=mock.ANY,
            timeout=mock.ANY,
        )


if __name__ == "__main__":
    unittest.main()
