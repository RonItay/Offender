import pytest


@pytest.mark.parametrize("cached", [True, False])
def test_search_symbol(linux_searcher, cached):
    linux_searcher.cached = cached
    assert linux_searcher.search_symbol("__libc_start_main", elf="libc.so.6") == [
        0x2A200
    ]


@pytest.mark.parametrize("cached", [True, False])
def test_search_symbol_size(linux_searcher, cached):
    linux_searcher.cached = cached
    assert linux_searcher.search_symbol_size("__libc_start_main", elf="libc.so.6") == [
        334
    ]


@pytest.mark.parametrize("cached", [True, False])
def test_search_symbol_in_dwarf(linux_searcher, cached):
    linux_searcher.cached = cached
    assert linux_searcher.search_symbol("__libc_start_main_impl", elf="libc.so.6") == [
        0x2A200
    ]


@pytest.mark.parametrize("cached", [True, False])
def test_search_section(linux_searcher, cached):
    linux_searcher.cached = cached
    assert linux_searcher.search_section(name=".text", elf="libc.so.6") == [0x28800]


@pytest.mark.parametrize("cached", [True, False])
def test_search_section_size(linux_searcher, cached):
    linux_searcher.cached = cached
    assert linux_searcher.search_section_size(name=".text", elf="libc.so.6") == [
        0x18748D
    ]


def test_search_opcodes_using_string(linux_searcher):
    assert linux_searcher.search_opcodes(
        "mov rsi, qword ptr [rbp - 0x20]; mov rdi, qword ptr [rbp - 0x18]; mov rbx, qword ptr [rbp - 8]; leave; jmp rax;",
        elf="libc.so.6",
    ) == [612417, 613641]
