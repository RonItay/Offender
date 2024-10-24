import pytest

from offender.exceptions import InvalidELFError, FailedToFindOffsetError
from offender.offset.offset import Symbol, Opcodes, SymbolSize, FoundOffset, Offsets
from offender.offset.offset_config import (
    OffsetConfig,
    OffsetContext,
    FoundOffsets,
    OffsetChain,
    FoundOffsetChain,
)
from offender.utils.offset_factory import get_offset_from_multiple_options
from test.conftest import add_elf_to_offset_context


def test_raise_exception_when_required_offset_not_found(extractor):
    config = OffsetConfig(
        general=Offsets(
            offsets=[Symbol(name="not_found", data="there_is_no_symbol_like_this")]
        )
    )
    with pytest.raises(FailedToFindOffsetError):
        extractor.extract(config)


def test_no_exception_raised_for_optional_offset_not_found(extractor):
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(
                    name="not_found", data="there_is_no_symbol_like_this", optional=True
                )
            ]
        ),
        chains=[],
    )

    expected = OffsetContext(general=FoundOffsets(offsets=set()), chains=[])
    result = extractor.extract(config)
    assert result == expected


def test_find_symbol_from_dwarf(extractor):
    config = OffsetConfig(
        general=Offsets(
            offsets=[Symbol(name="libc_start_main_impl", data="__libc_start_main_impl")]
        ),
    )

    expected = add_elf_to_offset_context(
        OffsetContext(
            general=FoundOffsets(
                offsets={FoundOffset(name="libc_start_main_impl", value=0x2A200)}
            ),
            chains=[],
        )
    )

    result = extractor.extract(config)
    assert result == expected


def test_apply_modification(extractor):
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(
                    name="libc_start_main_impl",
                    data="__libc_start_main_impl",
                    modifications=lambda x, _: x + 10,
                )
            ]
        ),
    )

    expected = add_elf_to_offset_context(
        OffsetContext(
            general=FoundOffsets(
                offsets={FoundOffset(name="libc_start_main_impl", value=0x2A200 + 10)}
            ),
            chains=[],
        )
    )

    result = extractor.extract(config)
    assert result == expected


def test_exception_raised_when_offset_is_dependent_on_an_optional_offset_that_is_not_found(
    extractor,
):
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(name="doesnt_exist", data="doesnt_exist", optional=True),
                Symbol(
                    name="libc_start_main",
                    data="__libc_start_main",
                    dependencies=["doesnt_exist"],
                ),
            ]
        )
    )

    with pytest.raises(FailedToFindOffsetError):
        extractor.extract(config)


def test_apply_modification_from_dependency(extractor):
    libc_start_main_impl_address = 0x2A200
    libc_start_call_main_address = 0x2A150

    def _libc_start_call_main_modification(
        address, dependencies: dict[str, FoundOffset]
    ):
        # Make sure that libc_start_call_main has access only to its dependencies.
        assert list(dependencies.keys()) == ["libc_start_main_impl"]
        return address + dependencies["libc_start_main_impl"].value

    config = OffsetConfig(
        general=Offsets(
            offsets=[
                # get_domain_name is here to make sure that libc_start_call_main doesn't receive its value when modifying.
                Symbol(name="get_domain_name", data="getdomainname"),
                Symbol(
                    name="libc_start_main_impl",
                    data="__libc_start_main_impl",
                    dependencies=["get_domain_name"],
                ),
                Symbol(
                    name="libc_start_call_main",
                    data="__libc_start_call_main",
                    dependencies=["libc_start_main_impl"],
                    modifications=_libc_start_call_main_modification,
                ),
            ]
        ),
    )

    expected = add_elf_to_offset_context(
        OffsetContext(
            general=FoundOffsets(
                offsets={
                    FoundOffset(name="get_domain_name", value=0x11F080),
                    FoundOffset(
                        name="libc_start_main_impl", value=libc_start_main_impl_address
                    ),
                    FoundOffset(
                        name="libc_start_call_main",
                        value=libc_start_call_main_address
                        + libc_start_main_impl_address,
                    ),
                }
            ),
            chains=[],
        )
    )

    result = extractor.extract(config)
    assert result == expected


def test_apply_filter(extractor):
    recurring_opcode = "pop rbp; ret;"
    value_filtered_for = 0x00034534

    def _filter(offsets: list[int], dependencies):

        for offset in offsets:
            if offset == value_filtered_for:
                return offset
        else:
            raise ValueError("NOT FOUND")

    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Opcodes(
                    name="recurring_opcode",
                    data=recurring_opcode,
                    result_filter=_filter,
                )
            ]
        )
    )

    expected = add_elf_to_offset_context(
        OffsetContext(
            general=FoundOffsets(
                offsets={FoundOffset(name="recurring_opcode", value=value_filtered_for)}
            ),
            chains=[],
        )
    )

    result = extractor.extract(config)
    assert result == expected


def test_apply_filter_with_dependencies(extractor):
    # In this test we try to find the call rax opcode in libc_start_call_main
    def _filter_jmp_rax_inside_start_call_main(
        addresses: list[int], dependencies: dict[str, FoundOffset]
    ):
        libc_start_call_main_start = dependencies["libc_start_call_main"].value
        libc_start_call_main_end = (
            dependencies["libc_start_call_main"].value
            + dependencies["libc_start_call_main_size"].value
        )

        for address in addresses:
            if address in range(libc_start_call_main_start, libc_start_call_main_end):
                return address
        else:
            raise ValueError("NOT FOUND")

    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(name="libc_start_call_main", data="__libc_start_call_main"),
                SymbolSize(
                    name="libc_start_call_main_size", data="__libc_start_call_main"
                ),
                Opcodes(
                    name="call_rax",
                    data="call rax;",
                    dependencies=["libc_start_call_main", "libc_start_call_main_size"],
                    result_filter=_filter_jmp_rax_inside_start_call_main,
                ),
            ]
        )
    )

    expected = add_elf_to_offset_context(
        OffsetContext(
            general=FoundOffsets(
                offsets={
                    FoundOffset(name="libc_start_call_main", value=0x2A150),
                    FoundOffset(name="libc_start_call_main_size", value=0xA4),
                    FoundOffset(name="call_rax", value=0x2A1C8),
                }
            ),
            chains=[],
        )
    )

    result = extractor.extract(config)
    assert result == expected


def test_nested_dependencies(extractor):
    def test_dependencies(_, dependencies: dict):
        assert "libc_start_main_impl" in dependencies.keys()
        assert "get_domain_name" not in dependencies.keys()

        return 3  # dunder value

    config = OffsetConfig(
        general=Offsets(
            offsets=[
                # get_domain_name is here to make sure that libc_start_call_main doesn't receive its value when modifying.
                Symbol(name="get_domain_name", data="getdomainname"),
                Symbol(
                    name="libc_start_call_main",
                    data="__libc_start_call_main",
                    dependencies=[
                        Offsets(
                            offsets=[
                                Symbol(
                                    name="libc_start_main_impl",
                                    data="__libc_start_main_impl",
                                )
                            ]
                        )
                    ],
                    modifications=test_dependencies,
                ),
            ]
        )
    )

    extractor.extract(config)


def test_nested_dependencies_with_optional_offsets(extractor):
    def test_dependencies(_, dependencies: dict):
        assert "libc_start_main_impl" in dependencies.keys()
        assert "doesnt_exist" not in dependencies.keys()

        return 3  # dunder value

    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(
                    name="libc_start_call_main",
                    data="__libc_start_call_main",
                    dependencies=[
                        Offsets(
                            offsets=[
                                Symbol(
                                    name="libc_start_main_impl",
                                    data="__libc_start_main_impl",
                                ),
                                Symbol(
                                    name="doesnt_exist",
                                    data="doesnt_exist",
                                    optional=True,
                                ),
                            ]
                        )
                    ],
                    modifications=test_dependencies,
                ),
            ]
        )
    )

    extractor.extract(config)


def test_offset_factory_multiple_options(extractor):
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                get_offset_from_multiple_options(
                    name="result",
                    options=Offsets(
                        offsets=[
                            Symbol(
                                name="libc_start_call_main",
                                data="__libc_start_call_main",
                            ),
                            Symbol(name="doesnt_exists", data="doesnt exists"),
                        ]
                    ),
                )
            ]
        )
    )

    # Note that purposely no elf is specified.
    # TODO: what do in case of None in data and no ELF specified. Can I somehow inherit elf from dependencies? I think i can
    expected = OffsetContext(
        general=FoundOffsets(
            offsets={
                FoundOffset(name="result", value=0x2A150),
            }
        ),
        chains=[],
    )

    result = extractor.extract(config)
    assert result == expected


def test_raises_error_when_no_chain_is_found(extractor):
    config = OffsetConfig(
        general=Offsets(offsets=[]),
        chains=[
            OffsetChain(
                name="not_found_chain",
                chain=Offsets(
                    offsets=[
                        Symbol(name="not found", data="there_is_no_symbol_like_this")
                    ]
                ),
            )
        ],
    )
    with pytest.raises(FailedToFindOffsetError):
        extractor.extract(config)


def test_returns_valid_chain_when_one_is_found(extractor):
    config = OffsetConfig(
        general=Offsets(offsets=[]),
        chains=[
            OffsetChain(
                name="not_found_chain",
                chain=Offsets(
                    offsets=[
                        Symbol(name="not found", data="there_is_no_symbol_like_this")
                    ]
                ),
            ),
            OffsetChain(
                name="found_chain",
                chain=Offsets(
                    offsets=[
                        Symbol(
                            name="libc_start_main_impl", data="__libc_start_main_impl"
                        )
                    ]
                ),
            ),
        ],
    )
    expected = add_elf_to_offset_context(
        OffsetContext(
            general=FoundOffsets(offsets=set()),
            chains=[
                FoundOffsetChain(
                    name="found_chain",
                    chain=FoundOffsets(
                        offsets={
                            FoundOffset(name="libc_start_main_impl", value=0x2A200)
                        }
                    ),
                )
            ],
        ),
    )

    result = extractor.extract(config)
    assert result == expected


def test_extractor_no_data_symbol(extractor):
    def _return_five_modification(value, dependencies):
        return 5

    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(
                    name="no_data",
                    data=None,
                    modifications=_return_five_modification,
                    elfs=None,
                )
            ]
        )
    )

    expected = OffsetContext(
        general=FoundOffsets(offsets={FoundOffset(name="no_data", value=5, elfs=None)}),
        chains=[],
    )

    result = extractor.extract(config)
    assert result == expected


def test_bad_elf(extractor):
    config = OffsetConfig(
        general=Offsets(
            offsets=[Symbol(name="bad_elf", data="not real", elfs="doesnt exist")]
        ),
        chains=[],
    )

    with pytest.raises(InvalidELFError):
        extractor.extract(config)


def test_extractor_finds_offsets_in_correct_elfs(extractor_multiple_elfs):
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(name="in_libc.so.6", data="aio_cancel"),
                Symbol(name="in_libc.so.6_old", data="_dl_catch_error"),
            ]
        )
    )

    expected = OffsetContext(
        general=FoundOffsets(
            offsets={
                FoundOffset(name="in_libc.so.6", value=0xA5F50, elf="libc.so.6"),
                FoundOffset(
                    name="in_libc.so.6_old", value=0x15A540, elf="libc.so.6_old"
                ),
            }
        ),
        chains=[],
    )

    result = extractor_multiple_elfs.extract(config)
    assert result == expected


def test_extractor_only_looks_at_specified_elf(extractor_multiple_elfs):
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                # This symbol actually exists in the other elf. This test is here to check that extractor doesn't search
                # for it there
                Symbol(
                    name="not_in_libc.so.6", data="_dl_catch_error", elfs="libc.so.6"
                )
            ]
        )
    )

    with pytest.raises(FailedToFindOffsetError):
        extractor_multiple_elfs.extract(config)


def test_extractor_offset_has_list_of_elfs(extractor_multiple_elfs):
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(name="in_libc.so.6", data="aio_cancel", elfs=["libc.so.6"]),
                Symbol(
                    name="in_libc.so.6_old",
                    data="_dl_catch_error",
                    elfs=["libc.so.6_old"],
                ),
            ]
        )
    )

    expected = OffsetContext(
        general=FoundOffsets(
            offsets={
                FoundOffset(name="in_libc.so.6", value=0xA5F50, elf="libc.so.6"),
                FoundOffset(
                    name="in_libc.so.6_old", value=0x15A540, elf="libc.so.6_old"
                ),
            }
        ),
        chains=[],
    )

    result = extractor_multiple_elfs.extract(config)
    assert result == expected


def test_extractor_offset_has_callback_for_elfs(extractor_multiple_elfs):
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(
                    name="in_libc.so.6",
                    data="aio_cancel",
                    elfs=lambda elf: elf == "libc.so.6",
                ),
                Symbol(
                    name="in_libc.so.6_old",
                    data="_dl_catch_error",
                    elfs=lambda elf: elf == "libc.so.6_old",
                ),
            ]
        )
    )

    expected = OffsetContext(
        general=FoundOffsets(
            offsets={
                FoundOffset(name="in_libc.so.6", value=0xA5F50, elf="libc.so.6"),
                FoundOffset(
                    name="in_libc.so.6_old", value=0x15A540, elf="libc.so.6_old"
                ),
            }
        ),
        chains=[],
    )

    result = extractor_multiple_elfs.extract(config)
    assert result == expected
