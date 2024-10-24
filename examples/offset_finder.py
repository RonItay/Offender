"""
Example file: offset_extractor.py

Instantiate an OffsetFinder - The object responsible for coordinating extraction over multiple versions
The examples in this file are in increasing level of complexity, it is recommended to read them in order.
"""

from offender.offset.offset import Offsets, Symbol
from offender.offset.offset_config import OffsetConfig
from offender.offset_finder.offset_finder import OffsetFinder
from resources import RESOURCES_DIR


def configure_offset_finder():
    """
    Show simple instantiation of an OffsetFinder object

    """
    config = OffsetConfig(
        general=Offsets(
            offsets=[Symbol(name="libc_start_main", data="libc_Start_main")]
        )
    )
    # OffsetFinder orchestrates data extraction of an OffsetConfig over multiple elf versions.
    finder = OffsetFinder(config)

    # each "version" represents a version of the target program - which may contain multiple different ELFs.
    # Therefore, each version is a list of ELFs, each elf is a tuple, the original elf and its (optional) DWARF file.
    versions = {
        "version1": [
            (
                RESOURCES_DIR / "libc.so.6",
                RESOURCES_DIR / "64b17fbac799e68da7ebd9985ddf9b5cb375e6.debug",
            )
        ],
        "version2": [(RESOURCES_DIR / "libc.so.6_old", RESOURCES_DIR / "libc-2.32.so")],
    }

    # Extraction is initiated with the `find` method.
    # returns two results:
    #   1. All the found versions, which is a dictionary of version to their target OffsetContext
    #   2. List of all failed versions. (#TODO: add string containing failure reason)
    found_versions, failed_versions = finder.find(versions)

    print(found_versions)
    print(failed_versions)

    return found_versions, failed_versions


def write_and_read_from_database():
    """
    Shows creation and reading from Offsets DB
    """

    found_versions, failed_versions = configure_offset_finder()

    # Offsets found from OffsetFinder can be saved in a database for later use.
    # The database is just a serialization of the OffsetContext of the different versions.
    # The database contains two tables.
    #   1. Table for found versions. This table is a simple key - version name, to the serialized OffsetContext for that version.
    #   2. Table for failed versions. Just a single column with their name.
    OffsetFinder.write_to_db(
        path="offsets.db", found_offsets=found_versions, failed_versions=failed_versions
    )

    #
