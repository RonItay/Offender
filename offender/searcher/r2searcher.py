import json
import logging
from typing import Literal

import r2pipe

from offender.searcher.cachable_searcher import CachableSearcher, CachedData
from offender.searcher.searcher import searcher_return

logger = logging.getLogger(__name__)


class R2searcher(CachableSearcher):
    def __init__(
        self, binary_paths: list[tuple[str, str | None]], cached: bool = True
    ) -> None:
        super().__init__(binary_paths, cached)

        self.r2_pipes = {
            elf_name: (r2pipe.open(elf_binaries[0]), r2pipe.open(elf_binaries[1]))
            for elf_name, elf_binaries in self.elfs.items()
        }

        self._text_section_addresses: dict[str, tuple[int, int] | None] = {
            elf_name: None for elf_name in self.elfs.keys()
        }

    def _get_text_section_addresses(self, elf_name) -> tuple[int, int]:
        cached_text_section = self._text_section_addresses[elf_name]
        if cached_text_section is not None:
            return cached_text_section

        pipe = self.r2_pipes[elf_name][0]
        text_section_start, _, text_section_end = pipe.cmd("iS~.text").split(" ")[2:5]
        text_section_start, text_section_end = int(text_section_start, base=16), int(
            text_section_end, base=16
        )
        self._text_section_addresses[elf_name] = text_section_start, text_section_end

        return text_section_start, text_section_end

    @staticmethod
    def _extract_data_from_radare_symbol_result(
        r2_result: str,
        name: str,
        what_to_extract: Literal["address", "size"] = "address",
    ) -> int | None:
        for line in r2_result.splitlines():
            if name == line.split()[-1]:
                if what_to_extract == "address":
                    return int(line.split()[2], base=16)
                elif what_to_extract == "size":
                    # TODO:
                    # Size part should theoretically be optional.
                    # I havent found a single case when a value is not present in `is`.
                    # How to recognize that case?
                    return int(line.split()[-2], base=10)
        else:
            return None

    @staticmethod
    def _extract_data_from_radare_section_result(
        r2_result: str,
        name: str,
        what_to_extract: Literal["address", "size"] = "address",
    ) -> int | None:
        for line in r2_result.splitlines():
            if name == line.split()[-1]:
                if what_to_extract == "address":
                    return int(line.split()[1], base=16)
                elif what_to_extract == "size":
                    # TODO:
                    # Size part should theoretically be optional.
                    # I haven't found a single case when a value is not present in `is`.
                    # How to recognize that case?
                    return int(line.split()[2], base=16)
        else:
            return None

    def _init_sections_cache(self, elf: str):
        sections = {}
        pipe = self.r2_pipes[elf][
            0
        ]  # Searching section in dwarf data doesnt really make sense
        sections_command_result: list[dict] = json.loads(pipe.cmd("iSj"))
        for section in sections_command_result:
            sections[section["name"]] = CachedData(
                address=section["vaddr"], size=section["size"]
            )

        self._sections_cache[elf] = sections

    def _init_symbols_cache(self, elf: str):
        symbols = {}
        # This joins both elf and dwarf
        for pipe in self.r2_pipes[elf]:
            symbols_command_result: list[dict] = json.loads(pipe.cmd("isj"))
            for symbol in symbols_command_result:
                symbols[symbol["name"]] = CachedData(
                    address=symbol["vaddr"], size=symbol["size"]
                )

        self._symbols_cache[elf] = symbols

    def _search_section_in_elf(self, name: str, elf: str) -> searcher_return:
        for pipe in self.r2_pipes[elf]:
            result = pipe.cmd(f"iS~{name}")
            if not result:
                return None

            result = self._extract_data_from_radare_section_result(result, name)
            if result is None:
                continue
            else:
                return [result]

        return None

    def _search_section_size_in_elf(self, name: str, elf: str):
        for pipe in self.r2_pipes[elf]:
            result = pipe.cmd(f"iS~{name}")

            if not result:
                return None

            result = self._extract_data_from_radare_section_result(result, name, "size")
            if result is None:
                continue
            else:
                return [result]

        return None

    def _search_symbol_in_elf(self, name: str, elf: str) -> searcher_return:
        for pipe in self.r2_pipes[elf]:
            result = pipe.cmd(f"is~{name}")

            if not result:
                continue

            result = self._extract_data_from_radare_symbol_result(result, name)
            if result is None:
                continue
            else:
                return [result]

        return None

    def _search_symbol_size_in_elf(self, name: str, elf: str) -> searcher_return:
        for pipe in self.r2_pipes[elf]:
            result = pipe.cmd(f"is~{name}")
            if not result:
                continue

            result = self._extract_data_from_radare_symbol_result(result, name, "size")
            if result is None:
                continue
            else:
                return [result]

        return None

    def search_opcodes(self, opcodes: bytes | str, elf: str) -> searcher_return:

        # Opcodes won't be in DWARF
        pipe = self.r2_pipes[elf][0]

        def _bytes_to_radare_format(to_format: bytes) -> str:
            return "".join(["{:02x}".format(_) for _ in to_format])

        def _extract_address_from_radare_result(r2_result: str) -> searcher_return:
            r2_results: list[dict] = json.loads(r2_result)
            if len(r2_results) == 0:
                return None

            offsets = [_["offset"] for _ in r2_results]

            text_section_start, text_section_end = self._get_text_section_addresses(elf)

            # Filter out found opcodes out of text section
            offsets = [
                offset
                for offset in offsets
                if offset in range(text_section_start, text_section_end)
            ]

            if offsets:
                return offsets
            else:
                return None

        if isinstance(opcodes, str):
            # Note the extra " inside the command string. It is necessary since ; is used to chain commands.
            # For some ungodly reason, radare2 doesn't have the option to return the results as json. (/aj doesnt work).
            # so this is some VERY ugly processing does on the result to fit _extract_address_from_radare_result
            # TODO: look if there is something im missing and there is a way to return things as json...

            # Opcodes won't be in the dwarf
            result = pipe.cmd(f'"/a {opcodes}"')
            relevant_addresses = [line.split()[0] for line in result.splitlines()]
            # God, please forgive me for what im about to do.
            result = json.dumps(
                [{"offset": int(value, base=16)} for value in relevant_addresses]
            )

        elif isinstance(opcodes, bytes):
            result = pipe.cmd(f"/xj {_bytes_to_radare_format(opcodes)}")
        else:
            return None

        if result:
            return _extract_address_from_radare_result(result)

        return None
