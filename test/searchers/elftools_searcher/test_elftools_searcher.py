def test_search_symbol(elftools_searcher):
    assert elftools_searcher.search_symbol("__libc_start_main", elf="libc.so.6") == [
        0x2A200
    ]


def test_search_symbol_size(elftools_searcher):
    assert elftools_searcher.search_symbol_size(
        "__libc_start_main", elf="libc.so.6"
    ) == [334]


def test_search_symbol_in_dwarf(elftools_searcher):
    assert elftools_searcher.search_symbol(
        "__libc_start_main_impl", elf="libc.so.6"
    ) == [0x2A200]


def test_search_section(elftools_searcher):
    assert elftools_searcher.search_section(name=".text", elf="libc.so.6") == [0x28800]


def test_search_section_size(elftools_searcher):
    assert elftools_searcher.search_section_size(name=".text", elf="libc.so.6") == [
        0x18748D
    ]
