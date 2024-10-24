from collections import Counter

from pydantic import BaseModel

from offender.exceptions import (
    DuplicateNamesError,
)
from offender.offset.offset import Offset, FoundOffset, Offsets


class FoundOffsets(BaseModel):
    offsets: set[FoundOffset]

    @property
    def map(self) -> dict[str, FoundOffset]:
        return {offset.name: offset for offset in self.offsets}


# sets of not primitive object are not serializable by pydantic, by design, so this is a workaround.
# This is supposed to be a background object for serialization/deserialization, and the user should not interact with it.
class SerializableFoundOffsets(BaseModel):
    offsets: list[FoundOffset]


class OffsetChain(BaseModel):
    name: str
    chain: Offsets

    def __hash__(self) -> int:
        return hash(self.name)


class FoundOffsetChain(BaseModel):
    name: str
    chain: FoundOffsets

    def __hash__(self):
        return hash(self.name)


class SerializableFoundOffsetChain(BaseModel):
    name: str
    chain: SerializableFoundOffsets

    def __hash__(self):
        return hash(self.name)


class OffsetConfig(BaseModel):
    """
    Class containing the offsets to be found.
    members:
        general - A list of general offsets to be found.
                  An offset in the general offset list can ONLY depend on offsets in the general offset lists.
                  Offsets inside the list cannot have duplicate names.
        chains - A list of Offset chains (for ROP chains).
                 An offset inside an Offset chain can Only depend on offsets in the general list and offsets in the SAME chain.
                 offsets within the same chain cannot share the same name.
    """

    general: Offsets | None
    chains: set[OffsetChain] | None = None

    def model_post_init(self, _):
        self._check_for_duplicates()

    @property
    def ordered_general(self) -> list[Offset]:
        try:
            return self._ordered_general
        except AttributeError:
            if self.general is None:
                self._ordered_general: list[Offset] = []
            else:
                self._ordered_general: list[Offset] = self.general.generate_extracting_order()  # type: ignore[no-redef]

            return self._ordered_general

    @property
    def ordered_chains(self) -> dict[str, list[Offset]]:
        try:
            if self.chains is None:
                return {}
            else:
                return self._ordered_chains
        except AttributeError:

            self._ordered_chains: dict[str, list[Offset]] = {}
            if self.chains is not None:
                for chain in self.chains:
                    self._ordered_chains[chain.name] = (
                        chain.chain.generate_extracting_order(
                            self.general.map if self.general is not None else None
                        )
                    )

            return self._ordered_chains

    def _check_for_duplicates(self):
        # check for duplicate names between general and chains:
        if self.chains is None:
            return

        for chain in self.chains:
            offsets_chain = chain.chain.offsets
            offsets_general = self.general.offsets if self.general is not None else []
            names = Counter([offset.name for offset in offsets_chain + offsets_general])
            if list(filter(lambda _: _ > 1, names.values())):
                raise DuplicateNamesError(
                    f"Found duplicate names between chain {chain.name} and general!"
                )


class OffsetContext(BaseModel):
    general: FoundOffsets
    chains: set[FoundOffsetChain]


class SerializableOffsetContext(BaseModel):
    general: SerializableFoundOffsets
    chains: list[SerializableFoundOffsetChain]

    @classmethod
    def from_non_serializable(
        cls, context: OffsetContext
    ) -> "SerializableOffsetContext":
        return cls(
            general=SerializableFoundOffsets(
                offsets=[offset for offset in context.general.offsets]
            ),
            chains=[
                SerializableFoundOffsetChain(
                    name=chain.name,
                    chain=SerializableFoundOffsets(
                        offsets=[offset for offset in chain.chain.offsets]
                    ),
                )
                for chain in context.chains
            ],
        )

    def to_non_serializable(self) -> "OffsetContext":
        return OffsetContext(
            general=FoundOffsets(offsets=set(self.general.offsets)),
            chains={
                FoundOffsetChain(
                    name=chain.name,
                    chain=FoundOffsets(offsets=set(chain.chain.offsets)),
                )
                for chain in self.chains
            },
        )
