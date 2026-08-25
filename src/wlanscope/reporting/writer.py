from __future__ import annotations

import os
import tempfile
from pathlib import Path


class ReportWriteError(RuntimeError):
    pass


def write_report(path: Path, content: str, force: bool = False) -> int:
    target = Path(path)
    parent = target.parent
    if not parent.exists():
        raise ReportWriteError("The report parent directory does not exist")
    if not parent.is_dir():
        raise ReportWriteError("The report parent path is not a directory")
    if target.exists():
        if target.is_dir():
            raise ReportWriteError("The report path identifies a directory")
        if not force:
            raise ReportWriteError("The report file already exists; use --force to overwrite it")

    normalized = content if content.endswith("\n") else f"{content}\n"
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            written = stream.write(normalized)
            stream.flush()
            os.fsync(stream.fileno())
        if force:
            os.replace(temporary, target)
        else:
            os.rename(temporary, target)
        temporary = None
        return written
    except OSError as error:
        raise ReportWriteError(
            f"Could not write the requested report: {error.strerror or error}"
        ) from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
