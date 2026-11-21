"""Read an attempt's real files without trusting its Git index or exclude settings."""

from __future__ import annotations

import hashlib
import os
import stat
import zlib
from pathlib import Path
from typing import Iterator

GITLINK_MODE = "160000"
SYMLINK_MODE = "120000"
EXECUTABLE_MODE = "100755"
REGULAR_MODE = "100644"
SPECIAL_MODE = "special"
_CHUNK_BYTES = 1024 * 1024


def parse_tree(listing: bytes) -> dict[str, tuple[str, str]]:
    """Parse `git ls-tree -r -z` output into path -> (mode, object id)."""

    entries: dict[str, tuple[str, str]] = {}
    for record in listing.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, _kind, object_id = metadata.decode("ascii").split()
        entries[os.fsdecode(raw_path)] = (mode, object_id)
    return entries


def walk_worktree(worktree: Path, gitlinks: set[str]) -> dict[str, str]:
    """Return every real path and its Git-style mode, without following symlinks."""

    found: dict[str, str] = {}

    def fail(error: OSError) -> None:
        raise error

    for root, directories, files in os.walk(worktree, onerror=fail, followlinks=False):
        relative_root = os.path.relpath(root, worktree)
        prefix = "" if relative_root == "." else f"{relative_root}/"
        if not prefix and ".git" in directories:
            directories.remove(".git")
        for name in list(directories):
            path = f"{prefix}{name}"
            full = os.path.join(root, name)
            if os.path.islink(full):
                directories.remove(name)
                found[path] = SYMLINK_MODE
            elif path in gitlinks:
                directories.remove(name)
                found[path] = GITLINK_MODE
        for name in files:
            if not prefix and name == ".git":
                continue
            path = f"{prefix}{name}"
            found[path] = _file_mode(os.lstat(os.path.join(root, name)))
    return found


def _file_mode(info: os.stat_result) -> str:
    if stat.S_ISLNK(info.st_mode):
        return SYMLINK_MODE
    if not stat.S_ISREG(info.st_mode):
        return SPECIAL_MODE
    return EXECUTABLE_MODE if info.st_mode & stat.S_IXUSR else REGULAR_MODE


def _blob_chunks(path: Path, mode: str) -> Iterator[bytes]:
    if mode == SYMLINK_MODE:
        target = os.fsencode(os.readlink(path))
        yield f"blob {len(target)}\0".encode("ascii")
        yield target
        return

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"not_a_regular_file: {path}")
        remaining = info.st_size
        yield f"blob {remaining}\0".encode("ascii")
        while remaining:
            chunk = handle.read(min(_CHUNK_BYTES, remaining))
            if not chunk:
                raise OSError(f"file_changed_while_reading: {path}")
            remaining -= len(chunk)
            yield chunk
        if handle.read(1):
            raise OSError(f"file_changed_while_reading: {path}")


def blob_id(path: Path, mode: str, algorithm: str) -> str:
    """Hash raw file bytes as a Git blob, bypassing repository filters."""

    digest = hashlib.new(algorithm)
    for chunk in _blob_chunks(path, mode):
        digest.update(chunk)
    return digest.hexdigest()


def write_loose_blob(objects: Path, path: Path, mode: str, algorithm: str) -> str:
    """Store raw file bytes as a loose object in a disposable object directory."""

    digest = hashlib.new(algorithm)
    compressor = zlib.compressobj(1)
    temporary = objects / f"incoming-{os.getpid()}"
    with temporary.open("wb") as output:
        for chunk in _blob_chunks(path, mode):
            digest.update(chunk)
            output.write(compressor.compress(chunk))
        output.write(compressor.flush())
    object_id = digest.hexdigest()
    target = objects / object_id[:2] / object_id[2:]
    target.parent.mkdir(exist_ok=True)
    os.replace(temporary, target)
    return object_id
