import pytest

from offender.offset.offset import Symbol, Offsets
from offender.offset.offset_config import (
    OffsetConfig,
    OffsetChain,
)
from offender.exceptions import (
    DependencyLoopError,
    MissingDependencyError,
    DuplicateNamesError,
)


def test_config_orders_offsets_according_to_dependencies():
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(name="1", data="A", dependencies=["2", "4"]),
                Symbol(name="2", data="A", dependencies=["3"]),
                Symbol(name="3", data="A"),
            ]
        )
    )

    expected = [
        Symbol(name="3", data="A"),
        Symbol(name="2", data="A", dependencies=["3"]),
        Symbol(name="1", data="A", dependencies=["2", "4"]),
    ]
    assert expected == config.general.generate_extracting_order({"4": True})


def test_config_recognizes_missing_dependency():
    config = OffsetConfig(
        general=Offsets(offsets=[Symbol(name="1", data="A", dependencies=["2"])])
    )

    with pytest.raises(MissingDependencyError):
        config.general.generate_extracting_order()


def test_config_recognizes_dependency_loop():
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(name="1", data="A", dependencies=["2"]),
                Symbol(name="2", data="A", dependencies=["1"]),
            ]
        )
    )

    with pytest.raises(DependencyLoopError):
        # config.generate_extracting_order_given_dict(config.general.map)
        config.general.generate_extracting_order()


def test_config_recognizes_duplicate_names_in_general():
    with pytest.raises(DuplicateNamesError):
        OffsetConfig(
            general=Offsets(
                offsets=[
                    Symbol(name="duplicate_symbol", data="1"),
                    Symbol(name="duplicate_symbol", data="2"),
                ]
            )
        )


def test_config_recognizes_duplicate_names_between_general_and_chain():
    with pytest.raises(DuplicateNamesError):
        OffsetConfig(
            general=Offsets(offsets=[Symbol(name="duplicate_symbol", data="1")]),
            chains=[
                OffsetChain(
                    name="duplicate_chain",
                    chain=Offsets(offsets=[Symbol(name="duplicate_symbol", data="2")]),
                )
            ],
        )
