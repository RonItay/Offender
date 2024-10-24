class MoreThanOneSymbolFound(Exception):
    pass


class DependencyLoopError(Exception):
    pass


class MissingDependencyError(Exception):
    pass


class DuplicateNamesError(Exception):
    pass


class InvalidELFError(Exception):
    pass


class FailedToFindOffsetError(Exception):
    pass


class SearcherNotAvailableError(Exception):
    pass
