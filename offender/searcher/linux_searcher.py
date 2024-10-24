import re
import subprocess
from platform import system
from re import finditer
from subprocess import CalledProcessError
from tempfile import NamedTemporaryFile
from typing import Literal

import keystone

from offender.exceptions import SearcherNotAvailableError, FailedToFindOffsetError
from offender.searcher.cachable_searcher import CachableSearcher, CachedData
from offender.searcher.searcher import searcher_return
from offender.utils.import_utils import check_if_linux_package_exists


# This searcher leverages linux utilities
class LinuxSearcher(CachableSearcher):
    _readelf_section_line_structure = re.compile(
        r"\s+\[\s?\d+]\s+([\w|\.|-]+)\s+\w+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+).*"
    )

    def __init__(self, binary_paths: list[tuple[str, str | None]], cached: bool = True):
        if not system().lower().startswith("linux"):
            raise SearcherNotAvailableError(
                "Unable to initialize Linux Searcher: not running on linux."
            )

        if not all(
            [
                check_if_linux_package_exists(required_package)
                for required_package in ["nm", "readelf", "objcopy"]
            ]
        ):
            raise SearcherNotAvailableError(
                "Missing Linux packages, please update your binutils package."
            )

        super().__init__(binary_paths, cached)

    @staticmethod
    def _symbol_is_dynamic_symbol(symbol: str) -> bool:
        return "@" in symbol

    @staticmethod
    def search_symbol_in_elf(
        name: str, elf_path: str, what_to_get: Literal["address", "size"] = "address"
    ) -> int | None:

        data_offset_in_result = {"address": 0, "size": 1}
        symbol_sections = ["", "-D"]  # one checks .symtab, other checks .dynsym
        for symbol_section in symbol_sections:
            try:
                res = subprocess.run(
                    f"nm --no-sort -C -S {symbol_section} {elf_path} | grep {name}",
                    shell=True,
                    capture_output=True,
                )
            except CalledProcessError as e:
                raise FailedToFindOffsetError(
                    "Received exception while searching for symbol"
                ) from e

            if not res or not res.stdout:
                continue

            # remove @ for different versions of Dynamic symbols
            # This is not good at all
            # TODO: change so we can differentiate between different dynamic symbols
            found_symbols = [
                symbol.split("@")[0] for symbol in res.stdout.decode().splitlines()
            ]
            found_data = [
                int("0x" + symbol.split()[data_offset_in_result[what_to_get]], base=16)
                for symbol in found_symbols
                if symbol.split()[3] == name
            ]

            # If multiple symbols found, make sure they're all the same - all referencing to the same underlying symbol
            if not all([data == found_data[0] for data in found_data]):
                continue

            return found_data[0]

        return None

    @staticmethod
    def search_section_in_elf(
        name: str, elf_path: str, what_to_get: Literal["address", "size"] = "address"
    ) -> int | None:

        data_offset_in_result = {"address": 3, "size": 5}
        try:
            res = subprocess.run(
                f"readelf -S -W {elf_path} | grep {name}",
                shell=True,
                capture_output=True,
            )
        except CalledProcessError as e:
            raise FailedToFindOffsetError(
                "Received exception while searching for section"
            ) from e

        if not res or not res.stdout:
            return None

        found_sections = res.stdout.decode().splitlines()
        found_data = [
            int("0x" + section.split()[data_offset_in_result[what_to_get]], base=16)
            for section in found_sections
            if section.split()[1] == name
        ]

        # If multiple sections found, make sure they're all the same - all referencing to the same underlying symbol
        if not all([data == found_data[0] for data in found_data]):
            return None

        return found_data[0]

    def _init_symbols_cache(self, elf: str):
        symbols = {}
        for elf_to_search in self.elfs[elf]:
            symbols_sections = ["", "-D"]
            for section in symbols_sections:
                try:
                    res = subprocess.run(
                        f"nm --no-sort --quiet -C -S {section} {elf_to_search}",
                        shell=True,
                        capture_output=True,
                    )
                except CalledProcessError as e:
                    raise FailedToFindOffsetError(
                        "Received exception while searching for symbol"
                    ) from e

                found_symbols = [
                    symbol.split("@")[0].split()
                    for symbol in res.stdout.decode().splitlines()
                    if symbol.split()[0] != "U"
                ]
                for symbol in found_symbols:
                    try:
                        symbols[symbol[3]] = CachedData(
                            address=int("0x" + symbol[0], base=16),
                            size=int("0x" + symbol[1], base=16),
                        )
                    except (IndexError, ValueError):
                        # Symbols that dont fit this format do not interest us
                        pass

        self._symbols_cache[elf] = symbols

    def _init_sections_cache(self, elf: str):
        main_elf = self.elfs[elf][
            0
        ]  # It doesn'st make sense to search sections in debug elf
        sections = {}
        try:
            res = subprocess.run(
                f"readelf -S -W {main_elf}",
                shell=True,
                capture_output=True,
            )
        except CalledProcessError as e:
            raise FailedToFindOffsetError(
                "Received exception while searching for section"
            ) from e

        if not res or not res.stdout:
            return None

        found_sections = [
            _
            for _ in [
                self._readelf_section_line_structure.match(section)
                for section in res.stdout.decode().splitlines()
            ]
            if _ is not None
        ]

        for section in found_sections:
            sections[section.group(1)] = CachedData(
                address=int("0x" + section.group(2), base=16),
                size=int("0x" + section.group(3), base=16),
            )

        self._sections_cache[elf] = sections

    # This doesnt do a hard search in dwarf incase symbol is not found in symbol tables.
    # TODO: implement

    def _search_symbol_in_elf(self, name: str, elf: str) -> searcher_return:
        for elf_to_search in self.elfs[elf]:
            if elf_to_search is None:
                continue

            symbol_addr = self.search_symbol_in_elf(name, elf_to_search, "address")
            if symbol_addr is None:
                continue

            return [symbol_addr]

        else:
            return None

    def _search_symbol_size_in_elf(self, name: str, elf: str) -> searcher_return:
        for elf_to_search in self.elfs[elf]:
            if elf_to_search is None:
                continue

            symbol_size = self.search_symbol_in_elf(name, elf_to_search, "size")
            if symbol_size is None:
                continue

            return [symbol_size]

        else:
            return None

    def _search_section_in_elf(self, name: str, elf: str) -> searcher_return:
        for elf_to_search in self.elfs[elf]:
            if elf_to_search is None:
                continue

            section_addr = self.search_section_in_elf(name, elf_to_search, "address")
            if section_addr is None:
                continue

            return [section_addr]

        else:
            return None

    def _search_section_size_in_elf(self, name: str, elf: str) -> searcher_return:
        for elf_to_search in self.elfs[elf]:
            if elf_to_search is None:
                continue

            section_size = self.search_section_in_elf(name, elf_to_search, "size")
            if section_size is None:
                continue

            return [section_size]

        else:
            return None

    def search_opcodes(self, opcodes: str | bytes, elf: str) -> searcher_return:
        elf_to_search = self.elfs[elf][0]  # Dwarf information does not have code.

        text_section_base = self.search_section_in_elf(
            ".text", elf_to_search, "address"
        )
        if text_section_base is None:
            raise FailedToFindOffsetError(
                "Failed to find opcode because couldn't find .text section base"
            )
        if isinstance(opcodes, str):
            # Find Arch?!
            ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            encoded_opcodes, _ = ks.asm(opcodes, as_bytes=True)

        elif isinstance(opcodes, bytes):
            encoded_opcodes = opcodes

        else:
            raise ValueError(f"Opcodes have invalid type! {type(opcodes)}")

        with NamedTemporaryFile() as f:
            # get text section bytes
            res = subprocess.run(
                f"objcopy --dump-section .text={f.name} {elf_to_search}; cat {f.name}",
                shell=True,
                capture_output=True,
            )
            if not res or not res.stdout:
                return None

        possible_matches = [
            text_section_base + possible_match.start()
            for possible_match in finditer(encoded_opcodes, res.stdout)
        ]
        return possible_matches if possible_matches else None
