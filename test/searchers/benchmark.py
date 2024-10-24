"""
Benchmark test
run with pytest --benchmark-group-by=func benchmark.py to see a comparison of searchers performance.
"""

import pytest

from test.searchers.conftest import searcher_names


def multiple_search(searcher_func, expected_result, *args, **kwargs):
    num_of_searches = 10
    for _ in range(num_of_searches):
        assert searcher_func(*args, **kwargs) == expected_result


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_symbol(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    result = benchmark(searcher.search_symbol, "__libc_start_main", elf="libc.so.6")
    assert result == [0x2A200]


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_symbol_multiple(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    benchmark(
        multiple_search,
        searcher.search_symbol,
        [0x2A200],
        "__libc_start_main",
        elf="libc.so.6",
    )


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_symbol_not_found(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    result = benchmark(searcher.search_symbol, "not_found", elf="libc.so.6")
    assert result is None


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_symbol_not_found_multiple(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    benchmark(
        multiple_search, searcher.search_symbol, None, "not_found", elf="libc.so.6"
    )


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_symbol_size(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    result = benchmark(
        searcher.search_symbol_size, "__libc_start_main", elf="libc.so.6"
    )
    assert result == [334]


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_symbol_size_not_found(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    result = benchmark(searcher.search_symbol_size, "not_found", elf="libc.so.6")
    assert result is None


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_symbol_size_not_found_multiple(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    benchmark(
        multiple_search, searcher.search_symbol_size, None, "not_found", elf="libc.so.6"
    )


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_symbol_in_dwarf(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    assert benchmark(
        searcher.search_symbol, "__libc_start_main_impl", elf="libc.so.6"
    ) == [0x2A200]


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_symbol_in_dwarf_multiple(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    benchmark(
        multiple_search,
        searcher.search_symbol,
        [0x2A200],
        "__libc_start_main_impl",
        elf="libc.so.6",
    )


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_opcodes_using_string(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    assert benchmark(
        searcher.search_opcodes,
        "mov rsi, qword ptr [rbp - 0x20]; mov rdi, qword ptr [rbp - 0x18]; mov rbx, qword ptr [rbp - 8]; leave; jmp rax;",
        elf="libc.so.6",
    ) == [612417, 613641]


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_opcodes_using_string_multiple(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    multiple_search(
        searcher.search_opcodes,
        [612417, 613641],
        "mov rsi, qword ptr [rbp - 0x20]; mov rdi, qword ptr [rbp - 0x18]; mov rbx, qword ptr [rbp - 8]; leave; jmp rax;",
        elf="libc.so.6",
    )


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_opcodes_using_string_not_found(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    assert (
        benchmark(
            searcher.search_opcodes,
            "ret; " * 100,
            elf="libc.so.6",
        )
        is None
    )


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_opcodes_using_string_not_found_multiple(
    request, benchmark, searcher
):
    searcher = request.getfixturevalue(searcher)
    multiple_search(searcher.search_opcodes, None, "ret; " * 100, elf="libc.so.6")


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_section(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    assert benchmark(searcher.search_section, name=".text", elf="libc.so.6") == [
        0x28800
    ]


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_section_multiple(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    benchmark(multiple_search, searcher.search_section, [0x28800], ".text", "libc.so.6")


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_section_not_found(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    assert (
        benchmark(searcher.search_section, name="doesnt_exist", elf="libc.so.6") is None
    )


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_section_not_found_multiple(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    benchmark(
        multiple_search,
        searcher.search_section,
        None,
        name="doesnt_exist",
        elf="libc.so.6",
    )


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_section_size(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    assert benchmark(searcher.search_section_size, name=".text", elf="libc.so.6") == [
        0x18748D
    ]


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_section_size_multiple(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    benchmark(
        multiple_search,
        searcher.search_section_size,
        [0x18748D],
        name=".text",
        elf="libc.so.6",
    )


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_section_size_not_found(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    assert (
        benchmark(searcher.search_section_size, name="doesnt_exists", elf="libc.so.6")
        is None
    )


@pytest.mark.parametrize("searcher", searcher_names)
def test_benchmark_search_section_size_not_found_multiple(request, benchmark, searcher):
    searcher = request.getfixturevalue(searcher)
    benchmark(
        multiple_search,
        searcher.search_section_size,
        None,
        name="doesnt_exists",
        elf="libc.so.6",
    )
