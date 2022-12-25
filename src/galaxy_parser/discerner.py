# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import abc
import dataclasses
import difflib
import re

from typing import cast
from typing import Dict
from typing import Type
from typing import TypeVar
from typing import Optional

from galaxy_parser import exceptions


@dataclasses.dataclass
class Discernment:

    label: str
    discerned_name: str
    source: str
    galaxy: str
    raw_data: Dict

    def get_tag(self) -> str:
        return f'misp-galaxy:{self.galaxy}="{self.discerned_name}"'


class AbstractDiscerner(abc.ABC):
    """Interface for all discerners."""

    BLACKLIST = frozenset(
        [
            "encrypted",
            "malware",
            "phishing",
            "ransomware",
            "threat",
            "trojan",
            "backdoor",
        ]
    )

    @staticmethod
    def normalize(label: str) -> str:
        """Normalize a label removing spaces and converting it to lower case."""
        return label.strip().lower().replace(" ", "").replace("-", "").replace("_", "")

    @property
    @abc.abstractmethod
    def source(self) -> str:
        """Return the source of this discernment."""

    @property
    @abc.abstractmethod
    def galaxy(self) -> str:
        """Return the galaxy of this discernment."""

    @classmethod
    def _partial_match(cls, query_string: str, dataset_string: str) -> bool:
        """Return whether something should be considered a partial match."""
        return dataset_string.startswith(query_string)

    @abc.abstractmethod
    def _discern(self, label: str, include_partial_matches: bool = False) -> Dict[str, Dict]:
        """Do the discernment."""

    def discern(
        self,
        label: str,
        include_partial_matches: bool = False,
        hint: Optional[str] = None,
    ) -> Discernment:
        """Do the discernment."""
        discernments = self._discern(label, include_partial_matches)
        # sometimes we can get multiple discernments, so use the hint to select which one
        if len(discernments) > 1 and hint:
            normalized_hint = self.normalize(hint)
            # build a dictionary where keys are labels and values how similar they are to the hint
            scores = {
                k: difflib.SequenceMatcher(None, self.normalize(k), normalized_hint).ratio()
                for k in discernments.keys()
            }
            # pick as label the one which is most similar to the hint once normalized
            discerned_name = max(scores, key=scores.get)
            raw_data = discernments[discerned_name]
        else:
            discerned_name, raw_data = list(discernments.items())[0]
        return Discernment(
            label=label,
            discerned_name=discerned_name,
            source=self.source,
            galaxy=self.galaxy,
            raw_data=raw_data,
        )


class BaseDiscerner(AbstractDiscerner, abc.ABC):
    """Base class for standard discerners."""

    GALAXY_NAME = None

    SOURCE_NAME = None

    @classmethod
    def create_class(
        cls,
        cluster: str,
        source: Optional[str] = None,
    ) -> Type["BaseDiscernerSubType"]:
        """Dynamically create a new type given a cluster name."""
        if not source:
            source = "custom"
        class_name = f"DiscernerClass_{cluster}_{source}"
        return cast(
            Type["BaseDiscernerSubType"],
            type(class_name, (cls,), {"GALAXY_NAME": cluster, "SOURCE_NAME": source}),
        )

    def __init__(self, galaxy_manager: "galaxy_parser.galaxy.BaseGalaxyManagerSubType") -> None:
        """Constructor."""
        galaxy_object = galaxy_manager.get_galaxy(self.GALAXY_NAME)

        # Index all values and keep track of "original" and "unique" values
        self.entry_by_normalized_label = {}
        unique_labels = set([])
        for entry in galaxy_object["values"]:
            self.entry_by_normalized_label[self.normalize(entry["value"])] = entry
            unique_labels.add(entry["value"])
            # Malpedia Fix:
            #   if we have 'BlackMatter (Windows)' also add 'BlackMatter' so when we look
            #   for synonyms of DarkSide, we do not add new entry for 'BlackMatter'
            unique_labels.add(re.sub(r"[\(\[].*?[\)\]]", "", entry["value"]).strip(" "))

        # Analyze all data entries and get the synonyms from the "meta" structure which are new
        entry_by_normalized_label_synonym = {}
        for entry in self.entry_by_normalized_label.values():
            label_synonyms = [x for x in entry.get("meta", {}).get("synonyms", [])]
            for label_synonym in label_synonyms:
                if label_synonym not in unique_labels:
                    entry_by_normalized_label_synonym[self.normalize(label_synonym)] = entry

        # Combine
        self.entry_by_normalized_label |= entry_by_normalized_label_synonym
        self.unique_normalized_labels = set(self.entry_by_normalized_label.keys())

    @property
    def source(self) -> str:
        """Implement interface."""
        return self.SOURCE_NAME

    @property
    def galaxy(self) -> str:
        """Implement interface."""
        return self.GALAXY_NAME

    def _discern(self, label: str, include_partial_matches: bool = False) -> Dict[str, Dict]:
        """Do the discernment."""
        normalized_label = self.normalize(label)
        if normalized_label in self.BLACKLIST:
            raise exceptions.FailedDiscernment
        try:
            # after normalizing we try to get a precise match
            return {
                self.entry_by_normalized_label[normalized_label][
                    "value"
                ]: self.entry_by_normalized_label[normalized_label]
            }
        except KeyError:
            # if we fail we start considering whether using a partial would give us a result
            if include_partial_matches:
                ret = {}
                for unique_normalized_label in self.unique_normalized_labels:
                    # a partial match is partial in two ways:
                    #   1) because the label we are looking can match only one word
                    #   2) because the match is not really exact
                    if self._partial_match(normalized_label, unique_normalized_label):
                        ret[
                            self.entry_by_normalized_label[unique_normalized_label]["value"]
                        ] = self.entry_by_normalized_label[unique_normalized_label]
                # partial matches are partial so there can be more than one
                if ret:
                    return ret
            raise exceptions.FailedDiscernment


class MispActorDiscerner(BaseDiscerner):

    GALAXY_NAME = "threat-actor"

    SOURCE_NAME = "misp"


class MitreActorDiscerner(BaseDiscerner):

    GALAXY_NAME = "mitre-intrusion-set"

    SOURCE_NAME = "mitre"


class MalpediaFamilyDiscerner(BaseDiscerner):

    GALAXY_NAME = "malpedia"

    SOURCE_NAME = "malpedia"


class MispToolDiscerner(BaseDiscerner):

    GALAXY_NAME = "tool"

    SOURCE_NAME = "misp"


class MitreMalwareDiscerner(BaseDiscerner):

    GALAXY_NAME = "mitre-malware"

    SOURCE_NAME = "mitre"


class MitreToolDiscerner(BaseDiscerner):

    GALAXY_NAME = "mitre-tool"

    SOURCE_NAME = "mitre"


BaseDiscernerSubType = TypeVar("BaseDiscernerSubType", bound=BaseDiscerner)
