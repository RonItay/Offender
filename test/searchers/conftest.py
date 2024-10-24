import pytest

from offender.searcher.elftools_searcher import ElftoolsSearcher
from offender.searcher.linux_searcher import LinuxSearcher
from offender.searcher.r2searcher import R2searcher

searcher_names = ["r2searcher", "elftools_searcher", "linux_searcher"]


@pytest.fixture
def r2searcher(get_basic_resources):
    return R2searcher([get_basic_resources])


@pytest.fixture
def linux_searcher(get_basic_resources):
    return LinuxSearcher([get_basic_resources])


@pytest.fixture
def elftools_searcher(get_basic_resources):
    return ElftoolsSearcher([get_basic_resources])
