# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import abc
import collections
import contextlib
import functools
import json
import logging
import requests
import shutil
import types
import tempfile
import os

from tqdm.auto import tqdm

from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import TypeVar
from typing import Generator
from typing import Tuple

from galaxy_parser import discerner
from galaxy_parser import exceptions


class BaseGalaxyManager(abc.ABC):
    """Base galaxy manager with no loading method defined."""

    GALAXY_NAME_TO_TYPE = {
        "360net": "360net-threat-actor",
        "android": "android",
        "atrm": "atrm",
        "attck4fraud": "financial-fraud",
        "backdoor": "backdoor",
        "banker": "banker",
        "bhadra-framework": "bhadra-framework",
        "botnet": "botnet",
        "branded_vulnerability": "branded-vulnerability",
        "cancer": "disease",
        "cert-eu-govsector": "cert-eu-govsector",
        "china-defence-universities": "china-defence-universities",
        "cmtmf-attack-pattern": "cmtmf-attack-pattern",
        "country": "country",
        "cryptominers": "cryptominers",
        "election-guidelines": "guidelines",
        "exploit-kit": "exploit-kit",
        "handicap": "handicap",
        "malpedia": "malpedia",
        "microsoft-activity-group": "microsoft-activity-group",
        "misinfosec-amitt-misinformation-pattern": "amitt-misinformation-pattern",
        "mitre-attack-pattern": "mitre-attack-pattern",
        "mitre-course-of-action": "mitre-course-of-action",
        "mitre-enterprise-attack-attack-pattern": "mitre-enterprise-attack-attack-pattern",
        "mitre-enterprise-attack-course-of-action": "mitre-enterprise-attack-course-of-action",
        "mitre-enterprise-attack-intrusion-set": "mitre-enterprise-attack-intrusion-set",
        "mitre-enterprise-attack-malware": "mitre-enterprise-attack-malware",
        "mitre-enterprise-attack-tool": "mitre-enterprise-attack-tool",
        "mitre-ics-assets": "mitre-ics-assets",
        "mitre-ics-groups": "mitre-ics-groups",
        "mitre-ics-levels": "mitre-ics-levels",
        "mitre-ics-software": "mitre-ics-software",
        "mitre-ics-tactics": "mitre-ics-tactics",
        "mitre-ics-techniques": "mitre-ics-techniques",
        "mitre-intrusion-set": "mitre-intrusion-set",
        "mitre-malware": "mitre-malware",
        "mitre-mobile-attack-attack-pattern": "mitre-mobile-attack-attack-pattern",
        "mitre-mobile-attack-course-of-action": "mitre-mobile-attack-course-of-action",
        "mitre-mobile-attack-intrusion-set": "mitre-mobile-attack-intrusion-set",
        "mitre-mobile-attack-malware": "mitre-mobile-attack-malware",
        "mitre-mobile-attack-tool": "mitre-mobile-attack-tool",
        "mitre-pre-attack-attack-pattern": "mitre-pre-attack-attack-pattern",
        "mitre-pre-attack-intrusion-set": "mitre-pre-attack-intrusion-set",
        "mitre-tool": "mitre-tool",
        "o365-exchange-techniques": "cloud-security",
        "preventive-measure": "preventive-measure",
        "ransomware": "ransomware",
        "rat": "rat",
        "region": "region",
        "rsit": "rsit",
        "sector": "sector",
        "social-dark-patterns": "social-dark-patterns",
        "sod-matrix": "sod-matrix",
        "stealer": "stealer",
        "surveillance-vendor": "surveillance-vendor",
        "target-information": "target-information",
        "tds": "tds",
        "tea-matrix": "tea-matrix",
        "threat-actor": "threat-actor",
        "tool": "tool",
    }

    @classmethod
    def _validate_galaxy_names(cls, galaxy_names: Optional[List[str]] = None) -> List[str]:
        for galaxy_name in galaxy_names or []:
            if galaxy_name not in cls.GALAXY_NAME_TO_TYPE:
                raise exceptions.NonExistingGalaxy("Galaxy '%s' not found" % galaxy_name)
        return galaxy_names or list(cls.GALAXY_NAME_TO_TYPE.keys())

    def __init__(self) -> None:
        """Constructor."""
        self._logger = logging.getLogger(__name__)
        self._galaxies: Dict[str, Dict] = {}
        self._type_to_name: Dict[str, str] = {}
        self._name_to_type: Dict[str, str] = {}

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

    def create_discerners(self, source: str = None) -> List["discerner.BaseDiscernerSubType"]:
        """Return a list of dynamically created discerners."""
        discerners = []
        for galaxy_name in self.galaxy_names:
            new_type = discerner.BaseDiscerner.create_class(galaxy_name, source or "custom")
            discerners.append(new_type(self))
        return discerners

    def __iter__(self) -> Generator[Tuple[str, Dict], None, None]:
        """Iterate over the loaded galaxies."""
        yield from self._galaxies.items()


class GalaxyManagerMISP(BaseGalaxyManager):
    """Galaxy manager that relies on MISP to fetch galaxies."""

    @classmethod
    def _list_galaxies(cls, misp: "pymisp.PyMISP") -> Dict[str, "pymisp.MISPGalaxy"]:
        """Get galaxies from MISP."""
        galaxies = misp.galaxies(pythonify=True)
        if not galaxies:
            ret = misp.update_galaxies()
            if not ret["success"]:
                raise ValueError("Error updating the galaxies: {}".format(ret))
            galaxies = misp.galaxies(pythonify=True)
        return {x.type: x for x in galaxies}

    @classmethod
    def _parse_galaxy(cls, galaxy_misp_json: Dict[str, Any]) -> Dict[str, Any]:
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

    @classmethod
    def _get_galaxy_data(
        cls,
        misp: "pymisp.PyMISP",
        galaxy_obj: "pymisp.MISPGalaxy",
    ) -> Dict[str, Any]:
        """Get the galaxy object."""
        g = misp.get_galaxy(
            galaxy=galaxy_obj,
            withCluster=True,
            pythonify=False,
        )
        return cls._parse_galaxy(g)

    def __init__(
        self,
        misp: "pymisp.PyMISP",
        galaxy_names: Optional[List[str]] = None,
    ) -> None:
        """Constructor."""
        super(GalaxyManagerMISP, self).__init__()
        galaxies = self._list_galaxies(misp)
        for galaxy_name in self._validate_galaxy_names(galaxy_names):
            try:
                self._galaxies[galaxy_name] = self._get_galaxy_data(misp, galaxies[galaxy_name])
            except KeyError:
                print(f"Galaxy {galaxy_name} missing...")
                continue
            self._type_to_name[self._galaxies[galaxy_name]["type"]] = galaxy_name
            self._name_to_type[galaxy_name] = self._galaxies[galaxy_name]["type"]


class GalaxyManagerLocal(BaseGalaxyManager):
    """Galaxy manager that relies on galaxy clusters stored in a local directory."""

    DEFAULT_TIMEOUT = 60

    URL_MISP_SUBMODULES = "https://api.github.com/repos/MISP/MISP/contents/app/files/"

    @classmethod
    def _get_commit_hash(cls, version: str) -> Optional[str]:
        """Get the commit hash corresponding to the provided MISP version."""
        params = {"ref": f"v{version}"}
        response = requests.get(
            cls.URL_MISP_SUBMODULES, params=params, timeout=cls.DEFAULT_TIMEOUT
        )
        # iterate as long as we get the final url so can get the URL with the right parameters
        while response.history:
            response = requests.get(response.url, params=params, timeout=cls.DEFAULT_TIMEOUT)
        json_data = response.json()
        for data in json_data:
            if data["name"] == "misp-galaxy":
                return data["sha"]
        return None

    @classmethod
    def _parse_galaxy(cls, dict_data: Dict) -> Dict:
        """Add a tag field to a galaxy dictionary."""
        for cluster in dict_data["values"]:
            cluster["tag_name"] = f"misp-galaxy:{dict_data['type']}=\"{cluster['value']}\""
        return dict_data

    @classmethod
    def _get_galaxy_data(cls, galaxy_file_name: str) -> Dict:
        """Get the galaxy object."""
        with open(galaxy_file_name, "r") as f:
            return cls._parse_galaxy(json.load(f))

    @classmethod
    def _get_local_path(
        cls,
        directory: str,
        galaxy_name: str,
        commit_hash: Optional[str] = None,
    ) -> str:
        """Return local path of a galaxy file."""
        extension = f"{commit_hash[:7]}.json" if commit_hash else "json"
        return os.path.join(directory, f"{galaxy_name}.{extension}")

    def __init__(
        self,
        input_directory: str,
        galaxy_names: Optional[List[str]] = None,
        commit_hash: Optional[str] = None,
        misp_version: Optional[str] = None,
    ) -> None:
        """Constructor."""
        super(GalaxyManagerLocal, self).__init__()
        if commit_hash and misp_version:
            raise ValueError("You need to specify either 'commit_hash' or 'misp_version'")
        if misp_version:
            commit_hash = self._get_commit_hash(misp_version)
        for galaxy_name in self._validate_galaxy_names(galaxy_names):
            galaxy_fname = self._get_local_path(input_directory, galaxy_name, commit_hash)
            try:
                self._galaxies[galaxy_name] = self._get_galaxy_data(galaxy_fname)
            except FileNotFoundError:
                print(f"Galaxy {galaxy_fname} missing...")
                continue
            self._type_to_name[self._galaxies[galaxy_name]["type"]] = galaxy_name
            self._name_to_type[galaxy_name] = self._galaxies[galaxy_name]["type"]


class GalaxyManagerOnDemand(GalaxyManagerLocal):
    """A local galaxy manager that download clusters on demand."""

    URL_MISP_GALAXY = "https://raw.githubusercontent.com/MISP/misp-galaxy"

    @classmethod
    def _download_galaxy_data_to_file(
        cls,
        url: str,
        output_file_path: str,
        verbose: bool = False,
        force: bool = False,
    ) -> None:
        """Download a file to a given path."""
        ret = requests.get(url, stream=True, allow_redirects=True, timeout=cls.DEFAULT_TIMEOUT)
        ret.raise_for_status()
        file_size = int(ret.headers.get("Content-Length", 0))
        # we can not check 'os.path.getsize(output_file_path) == file_size' because it is gzipped
        if not force and os.path.exists(output_file_path):
            return
        file_name = os.path.basename(output_file_path)
        ret.raw.read = functools.partial(ret.raw.read, decode_content=True)
        with (
            tqdm.wrapattr(ret.raw, "read", total=file_size, desc=f"Downloading '{file_name}'")
            if verbose
            else contextlib.nullcontext(ret.raw) as raw_reader
        ):
            with open(output_file_path, "wb") as f:
                shutil.copyfileobj(raw_reader, f)

    @classmethod
    def _get_remote_url(
        cls,
        galaxy_name: str,
        commit_hash: Optional[str] = None,
    ) -> str:
        """Return the URL of the MISP galaxy cluster, possible pinned by commit hash."""
        reference = commit_hash or "main"
        return f"{cls.URL_MISP_GALAXY}/{reference}/clusters/{galaxy_name}.json"

    def __init__(
        self,
        cache_directory: str,
        galaxy_names: List[str] = None,
        commit_hash: Optional[str] = None,
        misp_version: Optional[str] = None,
        verbose: bool = False,
        force: bool = False,
    ) -> None:
        """Constructor."""
        if commit_hash and misp_version:
            raise ValueError("You need to specify either 'commit_hash' or 'misp_version'")
        if misp_version:
            commit_hash = self._get_commit_hash(misp_version)
        for galaxy_name in self._validate_galaxy_names(galaxy_names):
            self._download_galaxy_data_to_file(
                url=self._get_remote_url(galaxy_name, commit_hash),
                output_file_path=self._get_local_path(cache_directory, galaxy_name, commit_hash),
                verbose=verbose,
                force=force,
            )
        super(GalaxyManagerOnDemand, self).__init__(
            input_directory=cache_directory,
            galaxy_names=galaxy_names,
            commit_hash=commit_hash,
        )


class GalaxyManagerCustom(GalaxyManagerLocal):
    """A galaxy manger loading custom galaxy JSON data."""

    def __init__(self, galaxy_data: Dict[str, Any], galaxy_name: str) -> None:
        """Constructor."""
        self._get_galaxy_data = types.MethodType(lambda x, y: galaxy_data, GalaxyManagerCustom)
        super().__init__(
            input_directory=tempfile.gettempdir(),
            galaxy_names=[galaxy_name],
        )


BaseGalaxyManagerSubType = TypeVar("BaseGalaxyManagerSubType", bound=BaseGalaxyManager)
