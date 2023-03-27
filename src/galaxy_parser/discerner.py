# Copyright 2022 VMware, Inc.
# SPDX-License-Identifier: BSD-2
import abc
import dataclasses
import difflib
import logging
import re

from typing import cast
from typing import Dict
from typing import List
from typing import Type
from typing import TypeVar
from typing import Tuple
from typing import Optional

from galaxy_parser import exceptions


@dataclasses.dataclass
class Discernment:

    label: str
    discerned_name: str
    source: str
    galaxy: str
    raw_data: Dict

    def get_tag(self, resolve_local: bool = True) -> str:
        if resolve_local:
            return f'misp-galaxy:{self.galaxy}="{self.discerned_name}"'
        else:
            return self.raw_data["tag_name"]


class AbstractDiscerner(abc.ABC):
    """Interface for all discerners."""

    AV_CLASSES = frozenset(
        [
            "encrypted",
            "malware",
            "phishing",
            "ransomware",
            "threat",
            "trojan",
            "backdoor",
            "loader",
            "worm",
            "stealer",
        ]
    )

    @classmethod
    def normalize(cls, label: str) -> str:
        """Normalize a label removing spaces and converting it to lower case."""
        # remove left and right whitespace and convert to lower case
        norm_label = label.strip().lower()
        # remove all class labels
        norm_label = " ".join([x for x in norm_label.split() if x not in cls.AV_CLASSES])
        # remove all non-alphanum characters including spaces
        norm_label = re.sub(r"[^a-zA-Z0-9]+", "", norm_label)
        return norm_label

    @property
    @abc.abstractmethod
    def source(self) -> str:
        """Return the source of this discernment."""

    @property
    @abc.abstractmethod
    def galaxy(self) -> str:
        """Return the galaxy of this discernment."""

    @abc.abstractmethod
    def _discern(self, label: str, include_partial_matches: bool = False) -> Dict[str, Dict]:
        """Do the discernment."""

    def _select_using_hint(self, discernments: Dict[str, Dict], hint: str) -> Tuple[str, Dict]:
        """Select a discernment using the hint."""
        # use the hint only if we find it among the discernments
        if any(hint.casefold() in x.casefold() for x in discernments.keys()):
            normalized_hint = self.normalize(hint)
            # build a dictionary where keys are labels and values how similar they are to the hint
            scores = {
                k: difflib.SequenceMatcher(None, self.normalize(k), normalized_hint).ratio()
                for k in discernments.keys()
            }
            # pick as label the one which is most similar to the hint once normalized
            discerned_name = max(scores, key=scores.get)
            raw_data = discernments[discerned_name]
        # otherwise pick the first item
        else:
            discerned_name, raw_data = list(discernments.items())[0]
        return discerned_name, raw_data

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
            discerned_name, raw_data = self._select_using_hint(discernments, hint)
            self._logger.debug(
                "Discern - Input=%s, Hint=%s, Output=%s, Choices=%s",
                label,
                hint,
                discerned_name,
                list(discernments.keys()),
            )
        else:
            discerned_name, raw_data = list(discernments.items())[0]
            self._logger.debug(
                "Discern - Input=%s, Output=%s, Choices=%s",
                label,
                discerned_name,
                list(discernments.keys()),
            )
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

    PREFIX_PERCENTAGE = 90

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
        self._logger = logging.getLogger(__name__)
        galaxy_object = galaxy_manager.get_galaxy(self.GALAXY_NAME)

        # Index all values and keep track of "original" and "unique" values
        self.entry_by_norm_label = {}
        unique_labels = set([])
        for entry in galaxy_object["values"]:
            self.entry_by_norm_label[self.normalize(entry["value"])] = entry
            unique_labels.add(entry["value"])
            # Malpedia Fix:
            #   if we have 'BlackMatter (Windows)' also add 'BlackMatter' so when we look
            #   for synonyms of DarkSide, we do not add new entry for 'BlackMatter'
            unique_labels.add(re.sub(r"[\(\[].*?[\)\]]", "", entry["value"]).strip(" "))

        # Analyze all data entries and get the synonyms from the "meta" structure which are new
        entry_by_norm_label_synonym = {}
        for entry in self.entry_by_norm_label.values():
            label_synonyms = [x for x in entry.get("meta", {}).get("synonyms", [])]
            for label_synonym in label_synonyms:
                if label_synonym not in unique_labels:
                    entry_by_norm_label_synonym[self.normalize(label_synonym)] = entry

        # Combine
        self.entry_by_norm_label |= entry_by_norm_label_synonym
        self.unique_normalized_labels = set(self.entry_by_norm_label.keys())

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
        if normalized_label in self.AV_CLASSES:
            raise exceptions.FailedDiscernment
        try:
            # after normalizing we try to get a precise match
            return {
                self.entry_by_norm_label[normalized_label]["value"]: self.entry_by_norm_label[
                    normalized_label
                ]
            }
        except KeyError:
            # if we fail we start considering whether using a partial would give us a result
            if include_partial_matches:
                matches: List[str] = difflib.get_close_matches(
                    word=normalized_label,
                    possibilities=self.unique_normalized_labels,
                )
                # only keep matches with a common prefix
                prefix_len = len(normalized_label) / 100 * self.PREFIX_PERCENTAGE
                common_prefix_matches = [
                    x for x in matches if x.startswith(normalized_label[: int(prefix_len)])
                ]
                ret = {
                    self.entry_by_norm_label[x]["value"]: self.entry_by_norm_label[x]
                    for x in common_prefix_matches
                }
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
