import os.path
from pathlib import Path

import pytest

from offender.offset.offset import Offsets, Symbol
from offender.offset.offset_config import OffsetContext, OffsetConfig
from offender.offset.offset_extractor import OffsetExtractor
from offender.offset_finder.offset_finder import OffsetFinder
from resources import RESOURCES_DIR

TEST_OFFSET_DB = Path(__file__).parent / "test.db"


@pytest.fixture
def get_basic_resources() -> tuple[str, str]:
    return str(RESOURCES_DIR / "libc.so.6"), str(
        RESOURCES_DIR / "64b17fbac799e68da7ebd9985ddf9b5cb375e6.debug"
    )


def get_multiple_resources() -> list[tuple[str, str]]:
    return [
        (
            str(RESOURCES_DIR / "libc.so.6"),
            str(RESOURCES_DIR / "64b17fbac799e68da7ebd9985ddf9b5cb375e6.debug"),
        ),
        (str(RESOURCES_DIR / "libc.so.6_old"), str(RESOURCES_DIR / "libc-2.32.so")),
    ]


@pytest.fixture
def get_multiple_elf_resources_fixture() -> list[tuple[str, str]]:
    return get_multiple_resources()


@pytest.fixture
def extractor(
    get_basic_resources, searchers_list: list[str] | None = None
) -> OffsetExtractor:
    return OffsetExtractor([get_basic_resources], required_searchers=searchers_list)


@pytest.fixture
def extractor_multiple_elfs(get_multiple_elf_resources_fixture):
    return OffsetExtractor(get_multiple_elf_resources_fixture)


def add_elf_to_offset_context(offset_context: OffsetContext):
    for offset in offset_context.general.offsets:
        offset.elf = "libc.so.6"

    for chain in offset_context.chains or []:
        for offset in chain.chain.offsets:
            offset.elf = "libc.so.6"

    return offset_context


def get_finder_results():
    resources = get_multiple_resources()
    versions = {
        "version_1": [resources[0]],
        "version_2": [resources[0]],
        "version_not_found": [resources[1]],
    }

    # This offsets will be found in version_1 but not found in version_2
    config = OffsetConfig(
        general=Offsets(
            offsets=[Symbol(name="libc_start_main_impl", data="__libc_start_main_impl")]
        )
    )

    # Find offsets
    finder = OffsetFinder(config)
    return finder.find(versions)


@pytest.fixture
def get_finder_results_fixture(get_multiple_elf_resources_fixture):
    versions = {
        "version_1": [get_multiple_elf_resources_fixture[0]],
        "version_2": [get_multiple_elf_resources_fixture[1]],
    }

    # This offsets will be found in version_1 but not found in version_2
    config = OffsetConfig(
        general=Offsets(
            offsets=[Symbol(name="libc_start_main_impl", data="__libc_start_main_impl")]
        )
    )

    # Find offsets
    finder = OffsetFinder(config)
    return finder.find(versions)


@pytest.fixture
def offset_db():
    if os.path.isfile(TEST_OFFSET_DB):
        os.remove(TEST_OFFSET_DB)

    found_versions, failed_versions = get_finder_results()
    # Create DB
    OffsetFinder.write_to_db(TEST_OFFSET_DB, found_versions, failed_versions)

    return found_versions, failed_versions
