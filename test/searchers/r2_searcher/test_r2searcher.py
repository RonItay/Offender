import pytest


@pytest.mark.parametrize("cached", [True, False])
def test_search_symbol(r2searcher, cached):
    r2searcher.cached = cached
    assert r2searcher.search_symbol("__libc_start_main", elf="libc.so.6") == [0x2A200]


@pytest.mark.parametrize("cached", [True, False])
def test_search_symbol_size(r2searcher, cached):
    r2searcher.cached = cached
    assert r2searcher.search_symbol_size("__libc_start_main", elf="libc.so.6") == [334]


@pytest.mark.parametrize("cached", [True, False])
def test_search_symbol_in_dwarf(r2searcher, cached):
    r2searcher.cached = cached
    assert r2searcher.search_symbol("__libc_start_main_impl", elf="libc.so.6") == [
        0x2A200
    ]


# Add a test using bytes, compiling using keystone probably
def test_search_opcodes_using_string(r2searcher):
    assert r2searcher.search_opcodes(
        "mov rsi, qword ptr [rbp - 0x20]; mov rdi, qword ptr [rbp - 0x18]; mov rbx, qword ptr [rbp - 8]; leave; jmp rax;",
        elf="libc.so.6",
    ) == [612417, 613641]


@pytest.mark.parametrize("cached", [True, False])
def test_search_section(r2searcher, cached):
    r2searcher.cached = cached
    assert r2searcher.search_section(name=".text", elf="libc.so.6") == [0x28800]


@pytest.mark.parametrize("cached", [True, False])
def test_search_section_size(r2searcher, cached):
    r2searcher.cached = cached
    assert r2searcher.search_section_size(name=".text", elf="libc.so.6") == [0x18748D]
