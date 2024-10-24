from offender.exceptions import FailedToFindOffsetError
from offender.offset.offset import FoundOffset


def get_offset_within_symbol_filter(symbol_name: str):
    def _filter(offsets: list[int], dependencies: dict[str, FoundOffset]) -> int:
        symbol_start = dependencies[symbol_name].value
        symbol_end = symbol_start + dependencies[symbol_name + "_size"].value

        for offset in offsets:
            if offset in range(symbol_start, symbol_end):
                return offset

        else:
            raise FailedToFindOffsetError(
                f"Failed to find offset within symbol: {symbol_name}"
            )

    return _filter
