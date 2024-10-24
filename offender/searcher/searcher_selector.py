from pathlib import Path

from offender.exceptions import SearcherNotAvailableError
from offender.searcher.searcher import Searcher
from offender.utils.import_utils import (
    import_module_from_path,
    check_library_requirements,
    get_module_dependencies,
)

PACKAGE_NAME = "offender"
SEARCHERS_PATH = Path(__file__).parent


# Surprised that i couldn't find a library function for that
def _snake_case_to_camel_case(snake_case: str) -> str:
    return "".join(_.capitalize() for _ in snake_case.lower().split("_"))


def get_searcher(searcher_name: str) -> Searcher:
    # check if dependencies are fulfilled:

    dependencies = get_module_dependencies(PACKAGE_NAME, searcher_name)
    if not all([check_library_requirements(dependency) for dependency in dependencies]):
        raise SearcherNotAvailableError(
            f"Searcher {searcher_name} doesn't have all its dependencies met"
        )

    searcher_path = SEARCHERS_PATH / (searcher_name + ".py")
    try:
        module = import_module_from_path(searcher_path, searcher_name)
    except FileNotFoundError as e:
        raise SearcherNotAvailableError(
            f"searcher {searcher_name} not found in searcher directory, please make sure filename is correct: {e}"
        )
    try:
        return module.__getattribute__(_snake_case_to_camel_case(searcher_name))
    except AttributeError:
        raise SearcherNotAvailableError(
            f"Searcher {_snake_case_to_camel_case(searcher_name)} was not found in searcher module {searcher_name}, "
            f"Please make sure that searcher class name is CamelCase of searcher module name"
        )
