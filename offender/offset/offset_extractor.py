import logging

from offender.exceptions import FailedToFindOffsetError, SearcherNotAvailableError
from offender.offset.offset import Offset, FoundOffset, Offsets
from offender.offset.offset_config import (
    OffsetConfig,
    FoundOffsets,
    OffsetContext,
    FoundOffsetChain,
)
from offender.searcher.searcher import Searcher
from offender.searcher.searcher_config import known_searchers
from offender.searcher.searcher_selector import get_searcher

logger = logging.getLogger(__name__)


class OffsetExtractor:
    def __init__(
        self,
        binary_paths: list[tuple[str, str | None]],
        required_searchers: list[str] | None = None,
    ) -> None:
        logger.debug(f"Offset extractor initiated with:\n\tbinaries: {binary_paths}")
        self.searchers: dict[str, Searcher] = {}
        for searcher in (
            required_searchers if required_searchers is not None else known_searchers
        ):
            try:
                self.searchers[searcher] = get_searcher(searcher)(binary_paths)  # type: ignore[operator]
            except SearcherNotAvailableError as e:
                logger.warning(f"Requested Searcher {searcher} is unavailable: {e}")
                continue

        if not self.searchers:
            raise ValueError("No searchers available")

    def extract(self, config: OffsetConfig) -> OffsetContext:
        logger.debug("Beginning offset extraction")
        general = self._extract(config.ordered_general, None)

        search_chains = config.chains is not None and len(config.chains) != 0
        found_chains = (
            self._extract_chains(config.ordered_chains, general)
            if search_chains
            else set()
        )

        logger.debug("Finished offset extraction")
        return OffsetContext(general=general, chains=found_chains)

    def _extract_chains(
        self, ordered_chains: dict[str, list[Offset]], found_general: FoundOffsets
    ):
        found_chains = set()
        for name, chain in ordered_chains.items():
            logger.debug(f"Extracting offset of chain: {name}")
            try:
                found_chains.add(
                    FoundOffsetChain(
                        name=name, chain=self._extract(chain, found_general.map)
                    )
                )
            except FailedToFindOffsetError as e:
                # This particular chain failed, there might be other possible chains
                logger.info(f"Failed to find chain {name}: {e}")
                continue

        if len(found_chains) == 0:
            raise FailedToFindOffsetError("No valid chains found!")

        return found_chains

    def _extract(
        self, offsets: list[Offset], already_found: dict[str, FoundOffset] | None = None
    ) -> FoundOffsets:
        result = set()
        addresses: list[int]

        already_found = already_found if already_found is not None else {}
        for offset in offsets:
            try:
                if offset.data is None:
                    addresses, elf = [], None
                else:
                    addresses, elf = self._extract_offset(offset)
                logger.debug(
                    f"Successfully found offset: {offset.name}, with possible addresses: {addresses}"
                )

            except FailedToFindOffsetError:
                logger.warning(f"Failed to find offset: {offset}")
                if offset.optional:
                    continue
                else:
                    raise

            try:
                dependencies = {}
                for dependency in offset.dependencies:
                    if isinstance(dependency, str):
                        dependencies[dependency] = already_found[dependency]
                    elif isinstance(dependency, Offsets):
                        dependencies.update(self._extract(dependency.offsets, None).map)
                    elif isinstance(dependency, Offset):
                        dependencies.update(self._extract([dependency]))
                    else:
                        raise ValueError(
                            f"Dependency had invalid type - This is a bug! {dependency}"
                        )

            except (KeyError, FailedToFindOffsetError) as e:
                raise FailedToFindOffsetError(
                    f"Could not process offset {offset.name} because one of its dependencies wasn't found: {e}"
                ) from e

            found_offset = FoundOffset(
                name=offset.name,
                value=offset.modifications(
                    offset.result_filter(addresses, dependencies), dependencies
                ),
                elf=elf,
            )

            result.add(found_offset)

            # Add the found offset to the already found dict, so future offsets can use it.
            already_found[found_offset.name] = found_offset

        logger.debug("Finished offset extraction")
        return FoundOffsets(offsets=result)

    def _extract_offset(self, offset: Offset) -> tuple[list[int], str]:
        for searcher in self.searchers.values():
            try:
                addresses, elf = searcher.search(offset)
                if isinstance(addresses, int):
                    addresses = [addresses]

                return addresses, elf

            except FailedToFindOffsetError:
                logger.warning(
                    f"Searcher {type(searcher).__name__} fail to find offset {offset}"
                )

        else:
            raise FailedToFindOffsetError(f"Failed to find offset {offset}")
