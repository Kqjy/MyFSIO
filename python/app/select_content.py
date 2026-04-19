"""S3 SelectObjectContent SQL query execution using DuckDB."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Generator, Optional

try:
    import duckdb
    DUCKDB_AVAILABLE = True
except ImportError:
    DUCKDB_AVAILABLE = False


class SelectError(Exception):
    """Error during SELECT query execution."""
    pass


def execute_select_query(
    file_path: Path,
    expression: str,
    input_format: str,
    input_config: Dict[str, Any],
    output_format: str,
    output_config: Dict[str, Any],
    chunk_size: int = 65536,
) -> Generator[bytes, None, None]:
    """Execute SQL query on object content."""
    if not DUCKDB_AVAILABLE:
        raise SelectError("DuckDB is not installed. Install with: pip install duckdb")

    conn = duckdb.connect(":memory:")

    try:
        if input_format == "CSV":
            _load_csv(conn, file_path, input_config)
        elif input_format == "JSON":
            _load_json(conn, file_path, input_config)
        elif input_format == "Parquet":
            _load_parquet(conn, file_path)
        else:
            raise SelectError(f"Unsupported input format: {input_format}")

        normalized_expression = expression.replace("s3object", "data").replace("S3Object", "data")

        try:
            result = conn.execute(normalized_expression)
        except duckdb.Error as exc:
            raise SelectError(f"SQL execution error: {exc}")

        if output_format == "CSV":
            yield from _output_csv(result, output_config, chunk_size)
        elif output_format == "JSON":
            yield from _output_json(result, output_config, chunk_size)
        else:
            raise SelectError(f"Unsupported output format: {output_format}")

    finally:
        conn.close()


def _load_csv(conn, file_path: Path, config: Dict[str, Any]) -> None:
    """Load CSV file into DuckDB."""
    file_header_info = config.get("file_header_info", "NONE")
    delimiter = config.get("field_delimiter", ",")
    quote = config.get("quote_character", '"')

    header = file_header_info in ("USE", "IGNORE")
    path_str = str(file_path).replace("\\", "/")

    conn.execute(f"""
        CREATE TABLE data AS
        SELECT * FROM read_csv('{path_str}',
            header={header},
            delim='{delimiter}',
            quote='{quote}'
        )
    """)


def _load_json(conn, file_path: Path, config: Dict[str, Any]) -> None:
    """Load JSON file into DuckDB."""
    json_type = config.get("type", "DOCUMENT")
    path_str = str(file_path).replace("\\", "/")

    if json_type == "LINES":
        conn.execute(f"""
            CREATE TABLE data AS
            SELECT * FROM read_json_auto('{path_str}', format='newline_delimited')
        """)
    else:
        conn.execute(f"""
            CREATE TABLE data AS
            SELECT * FROM read_json_auto('{path_str}', format='array')
        """)


def _load_parquet(conn, file_path: Path) -> None:
    """Load Parquet file into DuckDB."""
    path_str = str(file_path).replace("\\", "/")
    conn.execute(f"CREATE TABLE data AS SELECT * FROM read_parquet('{path_str}')")


def _output_csv(
    result,
    config: Dict[str, Any],
    chunk_size: int,
) -> Generator[bytes, None, None]:
    """Output query results as CSV."""
    delimiter = config.get("field_delimiter", ",")
    record_delimiter = config.get("record_delimiter", "\n")
    quote = config.get("quote_character", '"')

    buffer = ""

    while True:
        rows = result.fetchmany(1000)
        if not rows:
            break

        for row in rows:
            fields = []
            for value in row:
                if value is None:
                    fields.append("")
                elif isinstance(value, str):
                    if delimiter in value or quote in value or record_delimiter in value:
                        escaped = value.replace(quote, quote + quote)
                        fields.append(f'{quote}{escaped}{quote}')
                    else:
                        fields.append(value)
                else:
                    fields.append(str(value))

            buffer += delimiter.join(fields) + record_delimiter

            while len(buffer) >= chunk_size:
                yield buffer[:chunk_size].encode("utf-8")
                buffer = buffer[chunk_size:]

    if buffer:
        yield buffer.encode("utf-8")


def _output_json(
    result,
    config: Dict[str, Any],
    chunk_size: int,
) -> Generator[bytes, None, None]:
    """Output query results as JSON Lines."""
    record_delimiter = config.get("record_delimiter", "\n")
    columns = [desc[0] for desc in result.description]

    buffer = ""

    while True:
        rows = result.fetchmany(1000)
        if not rows:
            break

        for row in rows:
            record = dict(zip(columns, row))
            buffer += json.dumps(record, default=str) + record_delimiter

            while len(buffer) >= chunk_size:
                yield buffer[:chunk_size].encode("utf-8")
                buffer = buffer[chunk_size:]

    if buffer:
        yield buffer.encode("utf-8")
