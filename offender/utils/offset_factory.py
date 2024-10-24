from offender.exceptions import FailedToFindOffsetError
from offender.offset.offset import Offsets, Offset, FoundOffset, _default_modification


def get_offset_from_multiple_options(
    name: str, options: Offsets, **offset_kwargs
) -> Offset:
    # make all options optional:
    options_names = list(options.map.keys())
    try:
        original_dependencies = offset_kwargs["dependencies"]
        del offset_kwargs["dependencies"]
    except KeyError:
        original_dependencies = []

    try:
        original_modifications = offset_kwargs["modifications"]
        del offset_kwargs["modifications"]
    except KeyError:
        original_modifications = _default_modification

    for offset in options.offsets:
        offset.optional = True

    def _options_selector(_, dependencies: dict[str, FoundOffset] | None) -> int:
        if dependencies is None:
            raise FailedToFindOffsetError(
                "Failed to select offset from dependencies, no dependencies found."
            )

        for optional in options_names:
            try:
                found = dependencies[optional]
                break
            except KeyError:
                continue
        else:
            raise FailedToFindOffsetError(
                f"Could not find offset {name} from options: {options_names}"
            )

        return found.value

    def new_modifications(
        value: int | None, dependencies: dict[str, FoundOffset] | None
    ) -> int:
        found_option = _options_selector(value, dependencies)
        return original_modifications(found_option, dependencies)

    return Offset(
        name=name,
        data=None,
        dependencies=original_dependencies + [options],
        modifications=new_modifications,
        **offset_kwargs,
    )
