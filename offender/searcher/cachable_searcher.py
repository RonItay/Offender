from dataclasses import dataclass
from typing import Literal

from offender.searcher.searcher import Searcher, searcher_return


@dataclass
class CachedData:
    address: int
    size: int | None


cache = dict[str, dict[str, CachedData]]

# opcodes have no size
opcodes_cache = dict[str, dict[str | bytes, int]]


class CachableSearcher(Searcher):
    def __init__(self, binary_paths: list[tuple[str, str | None]], cached: bool = True):
        super().__init__(binary_paths)

        self.cached = cached

        self._sections_cache: cache = {}
        self._symbols_cache: cache = {}
        self._opcodes_cache: opcodes_cache = {}

    def _init_symbols_cache(self, elf: str):
        raise NotImplementedError()

    def _init_sections_cache(self, elf: str):
        raise NotImplementedError()

    def _init_opcodes_cache(self, elf: str):
        raise NotImplementedError()

    def _search_symbols_cache(
        self, name: str, elf: str, what_to_search: Literal["address", "size"]
    ) -> searcher_return:
        if elf not in self._symbols_cache.keys():
            self._init_symbols_cache(elf)

        try:
            return [self._symbols_cache[elf][name].__getattribute__(what_to_search)]
        except KeyError:
            return None

    def _search_sections_cache(
        self, name: str, elf: str, what_to_search: Literal["address", "size"]
    ) -> searcher_return:
        if elf not in self._sections_cache.keys():
            self._init_sections_cache(elf)

        try:
            return [self._sections_cache[elf][name].__getattribute__(what_to_search)]
        except KeyError:
            return None

    def _search_opcodes_cache(self, opcodes: str | bytes, elf: str) -> searcher_return:
        if elf not in self._opcodes_cache.keys():
            self._init_opcodes_cache(elf)

        try:
            return [self._opcodes_cache[elf][opcodes]]
        except KeyError:
            return None

    def _search_symbol_in_elf(self, name: str, elf: str) -> searcher_return:
        raise NotImplementedError()

    def _search_symbol_size_in_elf(self, name: str, elf: str) -> searcher_return:
        raise NotImplementedError()

    def _search_section_in_elf(self, name: str, elf: str) -> searcher_return:
        raise NotImplementedError()

    def _search_section_size_in_elf(self, name: str, elf: str) -> searcher_return:
        raise NotImplementedError()

    def _search_opcodes_in_elf(self, opcodes: bytes | str, elf: str) -> searcher_return:
        raise NotImplementedError()

    def search_symbol(self, name: str, elf: str) -> searcher_return:
        if self.cached:
            try:
                return self._search_symbols_cache(name, elf, "address")
            except NotImplementedError:
                return self._search_symbol_in_elf(name, elf)

        else:
            return self._search_symbol_in_elf(name, elf)

    def search_symbol_size(self, name: str, elf: str) -> searcher_return:
        if self.cached:
            try:
                return self._search_symbols_cache(name, elf, "size")
            except NotImplementedError:
                return self._search_symbol_size_in_elf(name, elf)

        else:
            return self._search_symbol_size_in_elf(name, elf)

    def search_section(self, name: str, elf: str) -> searcher_return:
        if self.cached:
            try:
                return self._search_sections_cache(name, elf, "address")
            except NotImplementedError:
                return self._search_section_in_elf(name, elf)

        else:
            return self._search_section_in_elf(name, elf)

    def search_section_size(self, name: str, elf: str) -> searcher_return:
        if self.cached:
            try:
                return self._search_sections_cache(name, elf, "size")
            except NotImplementedError:
                return self._search_section_size_in_elf(name, elf)

        else:
            return self._search_section_size_in_elf(name, elf)

    def search_opcodes(self, opcodes: str | bytes, elf: str) -> searcher_return:
        if self.cached:
            try:
                return self._search_opcodes_cache(opcodes, elf)
            except NotImplementedError:
                return self._search_opcodes_in_elf(opcodes, elf)

        else:
            return self._search_opcodes_in_elf(opcodes, elf)
