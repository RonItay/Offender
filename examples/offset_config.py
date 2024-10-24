"""
Example file: offset_config.py

Define an offset config and extract its offsets.
The examples in this file are in increasing level of complexity, it is recommended to read them in order.
"""

from examples.offset_extractor import get_extractor
from offender.exceptions import FailedToFindOffsetError
from offender.offset.offset import Symbol, Offsets, Opcodes, SymbolSize, FoundOffset
from offender.offset.offset_config import OffsetConfig, OffsetContext, OffsetChain


def simple_general_config():
    """
    Simpleset example - showing basic usage of OffsetConfig and the OffsetExtractor.
    """

    # OffsetConfig object - contains the offsets to be found.
    # the "general" member: offsets which one would consider "general purpose", and can be a viable dependency for all other offsets.
    #                       It is an Offsets object, which is simple a list of offsets.
    # An Offset: The basic object to be found. has a name by which it is identified to other offsets, and data by which it is found.
    #            offsets come in different "flavors", representing different types of data to be found.
    #            Here the desire
    config = OffsetConfig(
        general=Offsets(
            offsets=[Symbol(name="libc_start_main", data="__libc_start_main")]
        )
    )

    extractor = get_extractor()

    # Extract by using the `extract` method
    # This will return an OffsetContext object
    # It is almost identical to the OffsetConfig object, but instead of Offset - has FoundOffset,
    # which just contains the offsets name and address.
    context: OffsetContext = extractor.extract(config)

    print(context)


def offset_with_modifications():
    """
    Show a simple use of the modification and filter functionalities of an offset.
    """

    # Modifying the resulting address.
    # The address of "__libc_start_main_impl" is extracted. Assuming the desired address is AFTER the `endbr64` instruction,
    # A modification can be added that increases the resulting address by 4 (the number of bytes of the `endbr64` instruction.
    # Modification function - A function that takes the desired address, and the Offset's dependencies - which will explained in further examples.
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(
                    name="libc_start_main_impl",
                    data="__libc_start_main_impl",
                    modifications=lambda address, _: address + 4,
                )
            ]
        )
    )

    print(get_extractor().extract(config))

    # Filtering the resulting addresses
    # Some offset searches may result in multiple hits, from which one address is filtered using the "result_filter" option.
    # Using the result_filter function for example, one can make sure that only a single hit exists, or create more complex logic using dependencies.
    # A result_filter function receives a list of found addresses for the desired Offset, and its dependencies.
    def _filter_only_single_result(addresses: list[int], dependencies):
        if len(addresses) > 1:
            raise ValueError("Too many hits!")

        return addresses[0]

    # Here a config with an offset that obviously has many hits is defined
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Opcodes(
                    name="ret_opcode",
                    data="ret",
                    result_filter=_filter_only_single_result,
                )
            ]
        )
    )

    try:
        get_extractor().extract(config)
    except ValueError as e:
        print(e)


def using_dependencies():
    """
    Shows how to use dependencies for Offsets
    """

    # Each offset can have dependencies. Those dependencies can be used in an offset's modifications and filter.
    # Here an offset is dependent on other offsets in `general`, they are referenced by their given name.
    # In `general`, each offset CAN depend on other offsets if specified.
    # The order in which one specifies the offsets doesn't matter (one can specify offset A that is depended on offset B before B is specified).

    # Assume the desired opcodes is the ret instruction in `__libc_start_main_impl`.
    # The address and size of `__libc_start_main_impl` can be extracted,
    # and the desired opcode offset can depend on them, and use them in its result_filter function.

    def _filter_in_libc_start_main_impl(
        offsets: list[int], dependencies: [str, FoundOffset]
    ):
        for offset in offsets:
            if offset in range(
                dependencies["libc_start_main_impl"],
                dependencies["libc_start_main_impl"]
                + dependencies["libc_start_main_impl_size"],
            ):
                return offset
        else:
            raise ValueError("No valid opcode found")

    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Symbol(
                    name="libc_start_main_impl",
                    data="__libc_start_main_impl",
                ),
                SymbolSize(
                    name="libc_start_main_impl_size",
                    data="__libc_start_main_impl",
                ),
                Opcodes(
                    name="ret_in_libc_start_main_impl",
                    data="ret",
                    dependencies=["libc_start_main_impl", "libc_start_main_impl_size"],
                    result_filter=_filter_in_libc_start_main_impl,
                ),
            ]
        )
    )

    print(get_extractor().extract(config))

    # In the previous example dependencies are "global" inside general.
    # An offset can have "anonymous" or "nested" dependencies, which will not be added to the global context and only
    # used for the offset's calculations.
    # In the previous example, assuming the address and size of __libc_start_main_impl aren't interesting.
    config = OffsetConfig(
        general=Offsets(
            offsets=[
                Opcodes(
                    name="ret_in_libc_start_main_impl",
                    data="ret",
                    dependencies=Offsets(
                        offsets=[
                            Symbol(
                                name="libc_start_main_impl",
                                data="__libc_start_main_impl",
                            ),
                            SymbolSize(
                                name="libc_start_main_impl_size",
                                data="__libc_start_main_impl",
                            ),
                        ]
                    ),
                    result_filter=_filter_in_libc_start_main_impl,
                )
            ]
        )
    )

    print(get_extractor().extract(config))


def chains_example():
    """
    Simple example showing the usage of chains
    """

    # The chains member: OffsetConfig is written with binary exploitation in mind, and chains represent different possible ROP chains.
    # Each chain consists of Offsets, and are INDEPENDENT of each other
    # (Offsets in chain A cannot depend on Offsets in Chain B, but can depend on Offsets in General)
    # Chains are OPTIONAL - meaning, that if multiple possible chains are supplied in OffsetConfig,
    # it is sufficient for AT-LEAST one chain to be found in order to not fail.
    # In case that multiple are found, all are returned.
    config = OffsetConfig(
        chains={
            OffsetChain(
                name="chain_one",
                chain=Offsets(
                    offsets=[Symbol(name="libc_start_main", data="libc_start_main")]
                ),
            ),
            OffsetChain(
                name="chain_two",
                chain=Offsets(offsets=[Symbol(name="msg_get", data="msgget")]),
            ),
        }
    )

    print(get_extractor().extract(config))

    config = OffsetConfig(
        chains={
            OffsetChain(
                name="chain_one",
                chain=Offsets(
                    offsets=[Symbol(name="libc_start_main", data="libc_start_main")]
                ),
            ),
            OffsetChain(
                name="chain_two",
                chain=Offsets(
                    offsets=[Symbol(name="doesnt_exist", data="obviously_doesnt_exist")]
                ),
            ),
        }
    )

    print(get_extractor().extract(config))

    # If NO chains are found, an exception is raised.
    config = OffsetConfig(
        chains={
            OffsetChain(
                name="chain_one",
                chain=Offsets(
                    offsets=[Symbol(name="doesnt_exist", data="obviously_doesnt_exist")]
                ),
            ),
            OffsetChain(
                name="chain_two",
                chain=Offsets(
                    offsets=[Symbol(name="doesnt_exist", data="obviously_doesnt_exist")]
                ),
            ),
        }
    )

    try:
        print(get_extractor().extract(config))
    except FailedToFindOffsetError as e:
        print(e)
