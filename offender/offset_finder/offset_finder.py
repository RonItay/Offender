from logging import getLogger
from pathlib import Path

from offender.exceptions import FailedToFindOffsetError
from offender.offset.offset_config import (
    OffsetConfig,
    OffsetContext,
    SerializableOffsetContext,
)
from offender.offset.offset_extractor import OffsetExtractor
from offender.offset_finder.offset_database import create_db, read_offsets_from_db

logger = getLogger(__name__)


class OffsetFinder:
    def __init__(self, config: OffsetConfig):
        self.config = config

    def find(
        self, versions: dict[str, list[tuple[str, str | None]]]
    ) -> tuple[dict[str, OffsetContext], list[str]]:
        found_offsets: dict[str, OffsetContext] = {}
        failed_versions = []
        for version_name, elfs in versions.items():
            try:
                found_offsets[version_name] = OffsetExtractor(elfs).extract(self.config)
                logger.info(f"Successfully found Offsets for {version_name}")
            except FailedToFindOffsetError as e:
                logger.error(f"Could not find Offsets for {version_name}: {e}")
                failed_versions.append(version_name)
                continue

        return found_offsets, failed_versions

    @staticmethod
    def write_to_db(
        path: str | Path,
        found_offsets: dict[str, OffsetContext],
        failed_versions: list[str],
    ):
        serializable = {
            name: str(
                SerializableOffsetContext.from_non_serializable(context).model_dump()
            )
            for name, context in found_offsets.items()
        }
        create_db(path, serializable, failed_versions)

    @staticmethod
    def read_offsets_from_db(
        path: str | Path, wanted_versions: str | None = None
    ) -> dict[str, OffsetContext]:
        versions_serialized = read_offsets_from_db(path, wanted_versions)
        versions = {
            version: SerializableOffsetContext.model_validate(
                context
            ).to_non_serializable()
            for version, context in versions_serialized.items()
        }

        return versions
