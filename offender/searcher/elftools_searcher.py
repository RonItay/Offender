import logging
from typing import IO, Any

from elftools.elf.elffile import ELFFile
from elftools.construct.lib.container import Container
from elftools.dwarf.die import DIE
from offender.searcher.searcher import Searcher, searcher_return

logger = logging.getLogger(__name__)


class ElftoolsSearcher(Searcher):
    class FileDescriptorManager:
        def __init__(self) -> None:
            self.fds: list[IO[Any]] = []

        def add(self, fd: IO[Any]) -> IO[Any]:
            self.fds.append(fd)
            return fd

        def close_all(self):
            for fd in self.fds:
                try:
                    fd.close()
                except Exception as e:
                    logger.error(f"pyelftools searcher failed to close open file {fd}")
                    raise e

    def __init__(
        self,
        binary_paths: list[tuple[str, str | None]],
        deep_dwarf_search: bool = False,
    ):
        super().__init__(binary_paths)
        self.deep_dwarf_search = deep_dwarf_search
        logger.debug("Initializing Pyelftools searcher")

        self.fd_manager = self.FileDescriptorManager()
        self.elf_to_elffile_mapping: dict[str, tuple[ELFFile, ELFFile | None]] = {
            elf_name: (
                ELFFile(self.fd_manager.add(open(elf_files[0], "rb"))),
                (
                    ELFFile(self.fd_manager.add(open(elf_files[1], "rb")))
                    if elf_files[1] is not None
                    else None
                ),
            )
            for elf_name, elf_files in self.elfs.items()
        }

        # Currently, for some reason, pyelftools doesn't load external dwarf files from .gnu_debuglink section
        # (while it does from .gnu_debugaltlink)
        # I opened an issue, we'll see how it wil develop.
        # Update, a PR fixing the issue was merged, need to wait for a new version, which might take a while.

    def __del__(self):
        self.fd_manager.close_all()

    def search_section(self, name: str, elf: str) -> searcher_return:
        elf_file = self.elf_to_elffile_mapping[elf][0]
        section = elf_file.get_section_by_name(name)
        if section is None:
            return None

        try:
            return [section.header["sh_offset"]]
        except KeyError:
            return None

    def search_section_size(self, name: str, elf: str) -> searcher_return:
        elf_file = self.elf_to_elffile_mapping[elf][0]
        section = elf_file.get_section_by_name(name)
        if section is None:
            return None

        try:
            return [section.data_size]
        except AttributeError:
            return None

    def search_symbol(self, name: str, elf) -> searcher_return:
        elf_and_dwarf = self.elf_to_elffile_mapping[elf]
        result = self._search_symbol_elf_and_dwarf(
            elf_and_dwarf,
            name,
            symbol_table_attribute="st_value",
            debug_information_entry_attribute="DW_AT_low_pc",
        )
        return [result] if result is not None else None

    def search_symbol_size(self, name: str, elf: str) -> searcher_return:
        elf_and_dwarf = self.elf_to_elffile_mapping[elf]
        result = self._search_symbol_elf_and_dwarf(
            elf_and_dwarf,
            name,
            symbol_table_attribute="st_size",
            debug_information_entry_attribute="DW_AT_high_pc",
        )
        return [result] if result is not None else None

    def _search_symbol_elf_and_dwarf(
        self,
        elf_and_dwarf: tuple[ELFFile, ELFFile | None],
        name: str,
        symbol_table_attribute: str,
        debug_information_entry_attribute: str,
    ) -> int | None:
        elf, dwarf = elf_and_dwarf
        try:
            return self._get_symbol_table_attribute_entry(elf, name)[symbol_table_attribute]  # type: ignore[index]
        except (KeyError, TypeError):
            pass

        if dwarf is None:
            return None

        try:
            return self._get_symbol_table_attribute_entry(dwarf, name)[symbol_table_attribute]  # type: ignore[index]
        except (KeyError, TypeError):
            pass

        if not self.deep_dwarf_search:
            return None

        try:
            return (
                self._get_dwarf_debug_information_entry(dwarf, name)
                .attributes[  # type: ignore[union-attr]
                    debug_information_entry_attribute
                ]
                .value
            )
        except (KeyError, TypeError):
            pass

        return None

    @staticmethod
    def _get_symbol_table_attribute_entry(
        elffile: ELFFile, name: str
    ) -> Container | None:
        symbol_section_names = [".symtab", ".dynsym"]
        for symbol_section in symbol_section_names:
            section = elffile.get_section_by_name(symbol_section)
            if not section:
                continue

            try:
                symbols = section.get_symbol_by_name(name)
            except AttributeError:
                continue
            if not symbols:
                continue

            if not len(symbols) == 1:

                # Check if entries are identical
                if all([symbols[0].entry == symbol.entry for symbol in symbols]):
                    return symbols[0].entry
                else:
                    logger.warning(
                        f"More than one symbol found for {name}, symbols: {[sym.entry for sym in symbols]}"
                    )
                    return None
            return symbols[0].entry

        else:
            return None

    @staticmethod
    def _get_dwarf_debug_information_entry(elffile: ELFFile, name: str) -> DIE | None:
        _dwarfinfo = elffile.get_dwarf_info()
        for cu in _dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                attr = die.attributes.get("DW_AT_name")
                if not attr:
                    continue

                if attr.value == name.encode():
                    return die

        return None

    def search_opcodes(self, opcodes: str | bytes, elf: str) -> searcher_return:
        raise NotImplementedError()
