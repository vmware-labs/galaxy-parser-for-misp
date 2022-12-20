# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import abc
import collections
import contextlib
import functools
import json
import logging
import os
import requests
import shutil

from tqdm.auto import tqdm

from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import TypeVar

from galaxy_parser import exceptions


class BaseGalaxyManager(abc.ABC):
    """Base galaxy manager with no loading method defined."""

    ALL_GALAXY_NAMES = frozenset([
        "360net",
        "android",
        "atrm",
        "attck4fraud",
        "backdoor",
        "banker",
        "bhadra-framework",
        "botnet",
        "branded_vulnerability",
        "cancer",
        "cert-eu-govsector",
        "china-defence-universities",
        "cmtmf-attack-pattern",
        "country",
        "cryptominers",
        "election-guidelines",
        "exploit-kit",
        "handicap",
        "malpedia",
        "microsoft-activity-group",
        "misinfosec-amitt-misinformation-pattern",
        "mitre-attack-pattern",
        "mitre-course-of-action",
        "mitre-enterprise-attack-attack-pattern",
        "mitre-enterprise-attack-course-of-action",
        "mitre-enterprise-attack-intrusion-set",
        "mitre-enterprise-attack-malware",
        "mitre-enterprise-attack-tool",
        "mitre-ics-assets",
        "mitre-ics-groups",
        "mitre-ics-levels",
        "mitre-ics-software",
        "mitre-ics-tactics",
        "mitre-ics-techniques",
        "mitre-intrusion-set",
        "mitre-malware",
        "mitre-mobile-attack-attack-pattern",
        "mitre-mobile-attack-course-of-action",
        "mitre-mobile-attack-intrusion-set",
        "mitre-mobile-attack-malware",
        "mitre-mobile-attack-tool",
        "mitre-pre-attack-attack-pattern",
        "mitre-pre-attack-intrusion-set",
        "mitre-tool",
        "o365-exchange-techniques",
        "preventive-measure",
        "ransomware",
        "rat",
        "region",
        "rsit",
        "sector",
        "social-dark-patterns",
        "sod-matrix",
        "stealer",
        "surveillance-vendor",
        "target-information",
        "tds",
        "tea-matrix",
        "threat-actor",
        "tool",
    ])

    def __init__(self, galaxy_names: Optional[List[str]] = None) -> None:
        """Constructor."""
        self._logger = logging.getLogger(__name__)
        for galaxy_name in galaxy_names or []:
            if galaxy_name not in self.ALL_GALAXY_NAMES:
                raise exceptions.NonExistingGalaxy("Galaxy '%s' not found" % galaxy_name)
        self._galaxy_names = galaxy_names or self.ALL_GALAXY_NAMES
        self._galaxies = {}
        self._type_to_name = {}
        self._name_to_type = {}
        self._logger = logging.getLogger(__name__)

    @property
    def galaxy_names(self) -> Iterable[str]:
        """Iterate over the galaxy names."""
        return self._galaxies.keys()

    def get_tag_prefix(self, galaxy_name: str) -> str:
        """Get the tag prefix of the galaxy."""
        return f"misp-galaxy:{self._name_to_type[galaxy_name]}"

    def get_galaxy(self, galaxy_name: str) -> Dict:
        """Get the galaxy data."""
        try:
            return self._galaxies[galaxy_name]
        except KeyError:
            raise exceptions.NonExistingGalaxy("Galaxy '%s' not found" % galaxy_name)


class GalaxyManagerMISP(BaseGalaxyManager):
    """Galaxy manager that relies on MISP to fetch galaxies."""

    @classmethod
    def get_galaxies_from_misp(cls, misp) -> Dict:
        """Get galaxies from MISP."""
        galaxies = misp.galaxies(pythonify=True)
        if not galaxies:
            ret = misp.update_galaxies()
            if not ret["success"]:
                raise ValueError("Error updating the galaxies: %s".format(ret))
        galaxies = misp.galaxies(pythonify=True)
        return {x.type: x for x in galaxies}

    @classmethod
    def parse_galaxy(cls, galaxy_misp_json: Dict) -> Dict:
        """Parse a galaxy object into something we can process."""
        galaxy_dict = galaxy_misp_json["Galaxy"]
        galaxy_dict["values"] = []
        for cluster in galaxy_misp_json["GalaxyCluster"]:
            cluster["meta"] = collections.defaultdict(set)
            for galaxy_element in cluster.get("GalaxyElement", []):
                if galaxy_element["key"] == "external_id":
                    cluster["meta"][galaxy_element["key"]] = galaxy_element["value"]
                else:
                    cluster["meta"][galaxy_element["key"]].add(galaxy_element["value"])
            del cluster["GalaxyElement"]
            del cluster["id"]
            del cluster["collection_uuid"]
            del cluster["galaxy_id"]
            galaxy_dict["values"].append(cluster)
        return galaxy_dict

    def __init__(self, misp, galaxy_names: Optional[List[str]] = None) -> None:
        """Constructor."""
        super(GalaxyManagerMISP, self).__init__(galaxy_names)
        galaxies_by_type = self.get_galaxies_from_misp(misp)
        for galaxy_name in self._galaxy_names:
            if galaxy_name not in galaxies_by_type:
                print(f"Galaxy {galaxy_name} missing...")
                continue
            g = misp.get_galaxy(galaxies_by_type[galaxy_name], withCluster=True, pythonify=False)
            self._galaxies[galaxy_name] = self.parse_galaxy(g)
            self._type_to_name[self._galaxies[galaxy_name]["type"]] = galaxy_name
            self._name_to_type[galaxy_name] = self._galaxies[galaxy_name]["type"]


class GalaxyManagerLocal(BaseGalaxyManager):
    """Galaxy manager that relies on galaxy clusters stored in a local directory."""

    @classmethod
    def generate_galaxy(cls, dict_data: Dict) -> Dict:
        """Add a tag field to a galaxy dictionary."""
        for cluster in dict_data["values"]:
            cluster["tag_name"] = f"misp-galaxy:{dict_data['type']}=\"{cluster['value']}\""
        return dict_data

    def __init__(
        self,
        input_directory: str,
        galaxy_names: Optional[List[str]] = None,
        commit_hash: Optional[str] = None,
    ):
        """Constructor."""
        super(GalaxyManagerLocal, self).__init__(galaxy_names)
        extension = f"{commit_hash[:7]}.json" if commit_hash else "json"
        for galaxy_name in self._galaxy_names:
            galaxy_fname = os.path.join(input_directory, f"{galaxy_name}.{extension}")
            if not os.path.exists(galaxy_fname):
                print(f"Galaxy {galaxy_name} missing...")
                continue
            with open(galaxy_fname, "r") as f:
                self._galaxies[galaxy_name] = self.generate_galaxy(json.load(f))
            self._type_to_name[self._galaxies[galaxy_name]["type"]] = galaxy_name
            self._name_to_type[galaxy_name] = self._galaxies[galaxy_name]["type"]


class GalaxyManagerOnDemand(GalaxyManagerLocal):
    """A local galaxy manager that download clusters on demand."""

    GH_CLUSTERS_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/{reference}/clusters/"

    GH_MAIN_BRANCH = "main"

    @classmethod
    def download(
        cls,
        url: str,
        output_file_path: str,
        verbose: bool = False,
        force: bool = False,
    ) -> None:
        """Download a file to a given path."""
        ret = requests.get(url, stream=True, allow_redirects=True)
        ret.raise_for_status()
        file_size = int(ret.headers.get("Content-Length", 0))
        # we can not check 'os.path.getsize(output_file_path) == file_size' because it is gzipped
        if not force and os.path.exists(output_file_path):
            return
        file_name = os.path.basename(output_file_path)
        ret.raw.read = functools.partial(ret.raw.read, decode_content=True)
        with (
            tqdm.wrapattr(ret.raw, "read", total=file_size, desc=f"Downloading '{file_name}'")
            if verbose else contextlib.nullcontext(ret.raw) as raw_reader
        ):
            with open(output_file_path, "wb") as f:
                shutil.copyfileobj(raw_reader, f)

    def __init__(
        self,
        cache_directory: str,
        galaxy_names: List[str] = None,
        commit_hash: Optional[str] = None,
        verbose: bool = False,
        force: bool = False,
    ):
        """Constructor."""
        reference = commit_hash or self.GH_MAIN_BRANCH
        extension = f"{commit_hash[:7]}.json" if commit_hash else "json"
        galaxy_url = self.GH_CLUSTERS_URL.format(reference=reference)
        for galaxy_name in galaxy_names:
            self.download(
                url=f"{galaxy_url}{galaxy_name}.json",
                output_file_path=os.path.join(cache_directory, f"{galaxy_name}.{extension}"),
                verbose=verbose,
                force=force,
            )
        super(GalaxyManagerOnDemand, self).__init__(cache_directory, galaxy_names, commit_hash)


BaseGalaxyManagerSubType = TypeVar("BaseGalaxyManagerSubType", bound=BaseGalaxyManager)
