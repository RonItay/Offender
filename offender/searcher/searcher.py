from pathlib import Path

from offender.exceptions import InvalidELFError, FailedToFindOffsetError
from offender.offset.offset import (
    Offset,
    Symbol,
    SymbolSize,
    Opcodes,
    Section,
    SectionSize,
)

search_return = tuple[list[int], str]
searcher_return = list[int] | None


class Searcher:
    def __init__(self, binary_paths: list[tuple[str, str | None]]):
        self.elfs: dict[str, tuple[str, str | None]] = {
            Path(binary_path[0]).name: binary_path for binary_path in binary_paths
        }
        self.function_mapping = {
            Symbol: self.search_symbol,
            SymbolSize: self.search_symbol_size,
            Opcodes: self.search_opcodes,
            Section: self.search_section,
            SectionSize: self.search_section_size,
        }

    def search(self, offset: Offset) -> search_return:

        elfs_to_search: list[str] = []
        known_elfs: list[str] = list(self.elfs.keys())

        if isinstance(offset.elfs, str):
            if offset.elfs not in known_elfs:
                raise InvalidELFError(
                    f"Offset {offset.name} requested in elf {offset.elfs} "
                    f"which is not in list of known elfs: {known_elfs}"
                )
            elfs_to_search = [offset.elfs]
        elif isinstance(offset.elfs, list):
            elfs_to_search = list(set(offset.elfs).intersection(set(known_elfs)))
            if not elfs_to_search:
                raise InvalidELFError(
                    f"Offset {offset.name} requested in one of the elfs: {offset.elfs} "
                    f"which is not in list of known elfs: {known_elfs}"
                )

        elif callable(offset.elfs):
            elfs_to_search = [elf for elf in known_elfs if offset.elfs(elf)]
            if not elfs_to_search:
                raise InvalidELFError(
                    InvalidELFError(
                        f"Offset {offset.name} requested elf using callback.\n"
                        f"Non if the known elfs fitted the callback: {known_elfs}"
                    )
                )

        elif offset.elfs is None:
            elfs_to_search = known_elfs

        else:
            raise InvalidELFError(
                f"Offset {offset.name} requested elfs is not of valid type! {offset.elfs}"
            )

        for elf_name in elfs_to_search:
            try:
                found_offsets = self.function_mapping[type(offset)](offset.data, elf_name)  # type: ignore[arg-type]
            except NotImplementedError:
                raise FailedToFindOffsetError(
                    f"Searcher {type(self).__name__} does not implement a search function for {type(Offset).__name__}"
                )

            if found_offsets is None:
                continue

            return found_offsets, elf_name
        else:
            raise FailedToFindOffsetError(f"Failed to find offset {offset}")

    def search_symbol(self, name: str, elf: str) -> searcher_return:
        raise NotImplementedError()

    def search_symbol_size(self, name: str, elf: str) -> searcher_return:
        raise NotImplementedError()

    def search_section(self, name: str, elf: str) -> searcher_return:
        raise NotImplementedError()

    def search_section_size(self, name: str, elf: str) -> searcher_return:
        raise NotImplementedError()

    def search_opcodes(self, opcodes: str | bytes, elf: str) -> searcher_return:
        raise NotImplementedError()
