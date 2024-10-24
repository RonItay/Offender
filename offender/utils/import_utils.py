from importlib import util as util, metadata as meta
from typing import Callable
from types import ModuleType
from subprocess import check_call, CalledProcessError
from packaging.version import Version


class ImportException(Exception):
    pass


def _only_major_and_minor(ver: Version) -> tuple[int, int]:
    return ver.major, ver.minor


COMPARISON_MAPPING: dict[str, Callable[[str, str], bool]] = {
    "==": lambda lib, ver: Version(meta.version(lib)) == Version(ver),
    ">=": lambda lib, ver: Version(meta.version(lib)) >= Version(ver),
    "<=": lambda lib, ver: Version(meta.version(lib)) <= Version(ver),
    "~=": lambda lib, ver: _only_major_and_minor(Version(meta.version(lib)))
    == _only_major_and_minor(Version(ver)),
}


def import_module_from_path(path, name: str = "dunder name") -> ModuleType | None:
    # Create a module spec from the given path
    spec = util.spec_from_file_location(name, path)

    if spec is None or spec.loader is None:
        raise ImportException(f"Failed to import module from path: {path}")

    # Load the module from the created spec
    module = util.module_from_spec(spec)
    if module is None:
        raise ImportException(f"Failed to import module from path: {path}")

    # Execute the module to make its attributes accessible
    spec.loader.exec_module(module)

    # Return the imported module
    return module


def check_library_requirements(lib_string: str) -> bool:
    try:
        for comparison in COMPARISON_MAPPING.keys():
            try:
                library, version = lib_string.split(comparison)

            except ValueError:
                # If this is the incorrect comparison, the split will result in a single element list,
                # and a ValueError will be raised when trying to assign in to two variables.
                continue

            # If the library isn't installed, a PackageNotFoundError exception will be raised
            return COMPARISON_MAPPING[comparison](library, version)

        # None of the comparisons fit, so it is probably just a dependency without a versions
        else:
            return bool(meta.version(lib_string))

    except meta.PackageNotFoundError:
        return False


def get_module_dependencies(package_name: str, module_name: str) -> list[str]:
    total_dependencies = meta.requires(package_name)
    if total_dependencies is None:
        return []

    specific_dependencies = [
        dep.split(";")[0]
        for dep in total_dependencies
        if f'extra == "{module_name}"'.replace("_", "-") in dep
    ]
    return specific_dependencies


def check_if_linux_package_exists(package: str) -> bool:
    try:
        check_call(f"{package} --version >/dev/null", shell=True)
        return True
    except CalledProcessError:
        return False
