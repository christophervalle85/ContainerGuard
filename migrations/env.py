import os

from alembic import context

from app.database import get_engine
from app.models import Base

config = context.config


def run_migrations(connection) -> None:
    schema = (
        connection.get_execution_options().get("schema_translate_map", {}).get(None)
    )
    context.configure(
        connection=connection,
        target_metadata=Base.metadata,
        version_table_schema=schema,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    context.configure(
        url=os.environ["DATABASE_URL"],
        target_metadata=Base.metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    connection = config.attributes.get("connection")
    if connection is not None:
        run_migrations(connection)
    else:
        engine = get_engine()
        try:
            with engine.connect() as connection:
                run_migrations(connection)
        finally:
            engine.dispose()
