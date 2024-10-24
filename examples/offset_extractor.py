"""
Example file: offset_extractor.py

Instantiate an OffsetExtractor - the object responsible for extracting data, and configure its behavior.
The examples in this file are in increasing level of complexity, it is recommended to read them in order.
"""

from offender.offset.offset_extractor import OffsetExtractor
from resources import RESOURCES_DIR


def get_extractor():
    """
    Simple instantiation of extractor
    """
    # Configuring the extractor object - this object parses given elfs for the offsets in the config.
    # binary paths: list of elfs to parse for the offset config.
    #               each elf is a pair - the binary and a dwarf file (If no dwarf file is present - it can be None)
    # OffsetExtractor is used by calling its `extract` method.
    extractor = OffsetExtractor(
        binary_paths=[
            (
                RESOURCES_DIR / "libc.so.6",
                RESOURCES_DIR / "64b17fbac799e68da7ebd9985ddf9b5cb375e6.debug",
            )
        ]
    )

    return extractor


def configure_searchers():
    # Each extractor is made up of multiple searchers, each independent and providing both general and specific functionality.
    # For each Offset, OffsetExtractor will iterate over all known searchers until one returns an anser.
    # If one wishes, one can configure which searchers will be available for the OffsetExtractor
    # Only the desired searchers will be dynamically loaded.
    extractor = OffsetExtractor(
        binary_paths=[
            (
                RESOURCES_DIR / "libc.so.6",
                RESOURCES_DIR / "64b17fbac799e68da7ebd9985ddf9b5cb375e6.debug",
            )
        ],
        required_searchers=["linux_searcher", "elftools_searcher"],
    )

    # Each searcher can later be configured on demand
    extractor.searchers["elftools_searcher"].deep_dwarf_search = True
