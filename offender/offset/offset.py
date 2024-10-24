from collections import Counter
from dataclasses import field
from typing import Any, Callable, Union

from pydantic import BaseModel

from offender.exceptions import (
    DuplicateNamesError,
    DependencyLoopError,
    MissingDependencyError,
)


def _default_modification(
    value: int | None, dependencies: dict[str, "FoundOffset"] | None = None
) -> int:
    if value is None:
        raise ValueError("Received None from filter in default modification")
    return value


def _default_filter(
    found_values: list[int], dependencies: dict[str, "FoundOffset"] | None = None
) -> int | None:
    # This is a very specific case in which the user entered an offset without data.
    # In this specific case it is expected that the user enter their own modification that generates a value.
    if not len(found_values):
        return None

    return found_values[0]


class Offset(BaseModel):
    """
    Basic class representing an offset to be extracted from given ELFs and Dwarfs.
    public members:
    - name: user given name for the Offset. Will be used to reference it.
            for example - libc_start_main
    - data: The data by which the Offset will be searched. for example __libc_start_main.
            Data can also be None and the offset won't be searched.
            This is useful in the case that an offset is simply a function of a previously found offset,
            and it is expected of the user to implement their own modification function.
    - elf: Which binary the Offset belongs to. If left null, the Offset finder will search all given binaries for it.
           A debug file is considered part of the elf it belongs to. For example, if elf A has debug file B,
           and the offset is a symbol in B, it is considered in A.
    - optional: weather this Offset is optional. A negative value will prompt an error if the offset is not found.
    - dependencies: A list of other Offsets which this Offset is dependent on.
                    Offset X is dependent on Offset Y means:
                    1. If X is not optional and Y is not found, an error will be prompted.
                    2. The value of Y will be passed to X's further calculation.
                    Value in dependencies can be used in filter and modifications functions.
                    An Offset can depend ONLY on offsets in the same `Offsets` object as themselves,
                    AND on nested `Offsets` object within their dependencies.

    - result_filter: Function that filters all possible offset values to singular one.
              An offset might have multiple hits (for example a ROP gadget might have multiple instances), and one of those needs to be chosen.
              The default action is choosing the first value found.
              This function receives the list of possible addresses to choose from, and the value of the offsets dependencies.

    - modifications: Function that alters the found offset.
                     This function receives the found offset, and dictionary containing the values of dependent offsets.
                     For example. if modifications = lambda _: _ + 4, an Offset was found at address 10,
                     The final result will be address 14.
    """

    name: str
    data: bytes | str | None
    elfs: str | list[str] | Callable[[str], bool] | None = None
    optional: bool = False
    # For some ungodly reason, | operator does not work when specifying class in quotations (thinks is a string)
    dependencies: list[Union[str, "Offset", "Offsets"]] = field(default_factory=list)
    modifications: Callable[[int | None, dict[str, "FoundOffset"] | None], int] = (
        _default_modification
    )
    result_filter: Callable[
        [list[int], dict[str, "FoundOffset"] | None], int | None
    ] = _default_filter

    def __hash__(self) -> int:
        return hash(self.name)


# Different type of offsets, each triggering a different searching mechanism
class Symbol(Offset):
    pass


class SymbolSize(Offset):
    pass


class Opcodes(Offset):
    pass


class Section(Offset):
    pass


class SectionSize(Offset):
    pass


class FoundOffset(BaseModel):
    name: str
    value: int
    elf: str | None = None

    def __hash__(self):
        return hash(self.name)


class Offsets(BaseModel):
    name: str = "anonymous"
    offsets: list[Offset]

    def model_post_init(self, _):
        names = Counter([offset.name for offset in self.offsets])
        if list(filter(lambda _: _ > 1, names.values())):
            raise DuplicateNamesError("Found duplicate names in general")

    # For quick access
    @property
    def map(self) -> dict[str, Offset]:
        return {offset.name: offset for offset in self.offsets}

    def __iter__(self):
        return self.offsets.__iter__()

    def generate_extracting_order(
        self, already_found: dict[str, Any] | None = None
    ) -> list[Offset]:

        # dictionary to be popped from
        offsets_pool = self.map
        # base unchanged truth
        offsets_to_order = self.map

        # TODO: Making those sets is more or less effective?
        searching: dict[str, bool] = {}
        found: dict[str, bool] = (
            already_found.copy() if already_found is not None else {}
        )
        result = []

        # Recursive functions
        def _enter_offset(offset: Offset):
            # Check for loops:
            if offset.name in searching:
                raise DependencyLoopError(
                    f"Loop found for offset {offset.name}. The looping offsets: {list(searching.keys())}"
                )

            searching[offset.name] = True

            for dependency in offset.dependencies:
                # Nested offsets are independent on outer ones so no need to take them into accounts.
                if isinstance(dependency, Offset | Offsets):
                    continue

                # If dependency is already found, then it is already in the resulting list
                if dependency in found:
                    continue

                try:
                    dependency_offset = offsets_to_order[dependency]
                except KeyError:
                    raise MissingDependencyError(
                        f"Offset {offset.name} dependent on: {dependency}, which doesnt exist!"
                    )

                _enter_offset(dependency_offset)

            result.append(offset)
            found[offset.name] = True
            del searching[offset.name]
            try:
                del offsets_pool[offset.name]
            # Already popped
            except KeyError:
                pass

        while True:
            try:
                name, offset_to_find = offsets_pool.popitem()
            except KeyError:
                break

            _enter_offset(offset_to_find)

        return result
