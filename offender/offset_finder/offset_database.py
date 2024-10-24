from pathlib import Path

from sqlalchemy import Table, Column, Integer, String, MetaData, create_engine
from sqlalchemy.orm import Session

meta = MetaData()

found_versions = Table(
    "found_versions",
    meta,
    Column("id", Integer, primary_key=True),
    Column("version", String),
    Column("offsets", String),
)

not_found_versions = Table(
    "not_found_versions",
    meta,
    Column("id", Integer, primary_key=True),
    Column("version", String),
)


def create_db(path: str | Path, offsets: dict[str, str], failed_versions: list[str]):
    engine = create_engine(f"sqlite:///{path}")
    meta.create_all(engine)
    session = Session(engine)
    session.execute(
        found_versions.insert(),
        [
            {"version": name, "offsets": offset_context}
            for name, offset_context in offsets.items()
        ],
    )

    session.execute(
        not_found_versions.insert(),
        [{"version": version} for version in failed_versions],
    )

    session.commit()
    session.close()


def read_offsets_from_db(path: str | Path, version: str | None) -> dict[str, str]:
    engine = create_engine(f"sqlite:///{path}")
    query_result = Session(engine).execute(
        found_versions.select().where(
            found_versions.c.version == version if version is not None else True
        )
    )

    return {result[1]: eval(result[2]) for result in query_result}
