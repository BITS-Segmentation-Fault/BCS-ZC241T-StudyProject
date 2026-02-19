import getpass
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from sandbox.demo.fs import write_text


def _read_subid_ranges(path: Path | str, user: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []

    try:
        lines = Path(path).read_text().splitlines()
    except OSError as e:
        raise ValueError(f"cannot read {path}: {e}")

    for line in lines:
        # remove comments first
        parts = line.split("#", 1)[0].strip().split(":")
        if len(parts) != 3:
            continue

        if parts[0] != user:
            continue

        try:
            uid = int(parts[1])
            count = int(parts[2])
        except ValueError:
            raise ValueError(f"invalid numeric value in {path}: {line}")

        if uid < 0 or count <= 0:
            raise ValueError(f"invalid range in {path}: {line}")

        ranges.append((uid, count))

    if not ranges:
        raise ValueError(f"no subid entries for user '{user}' in {path}")

    ranges.sort(key=lambda r: r[0])

    return ranges


def _build_idmap(
    host_id: int, subid_ranges: Iterable[tuple[int, int]]
) -> list[tuple[int, int, int]]:
    idmap = [(0, host_id, 1)]
    uid = 1
    for loweruid, count in subid_ranges:
        idmap.append((uid, loweruid, count))
        uid += count
    return idmap


def _run_idmap_helper(
    helper: str,
    child_pid: int,
    idmap: list[tuple[int, int, int]],
    *,
    logger: logging.Logger,
) -> None:
    helper_path = shutil.which(helper)
    if not helper_path:
        raise RuntimeError(f"{helper} not found in PATH")

    argv = [helper_path, str(child_pid)]
    for uid, loweruid, count in idmap:
        argv += [str(uid), str(loweruid), str(count)]

    logger.debug(f"running {" ".join(argv)}")
    try:
        subprocess.run(argv, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = str(e.stderr).strip() or str(e.stdout).strip() or repr(e)
        raise RuntimeError(f"{helper} failed: {msg}") from e


def write_idmaps(
    child_pid: int, host_uid: int, host_gid: int, *, logger: logging.Logger
) -> None:
    proc = Path(f"/proc/{child_pid}")
    if not proc.exists():
        raise ValueError(f"process {child_pid} does not exist: {proc}")

    setgroups_path = proc / "setgroups"

    user = getpass.getuser()
    subuid_ranges = _read_subid_ranges("/etc/subuid", user)
    subgid_ranges = _read_subid_ranges("/etc/subgid", user)

    uidmap = _build_idmap(host_uid, subuid_ranges)
    gidmap = _build_idmap(host_gid, subgid_ranges)

    if setgroups_path.exists():
        try:
            write_text(setgroups_path, "deny\n")
            logger.debug(f"wrote {setgroups_path}: deny")
        except OSError as e:
            raise RuntimeError(f"failed to write {setgroups_path}: {e}") from e

    _run_idmap_helper("newuidmap", child_pid, uidmap, logger=logger)
    logger.debug(f"newuidmap applied: {uidmap}")

    _run_idmap_helper("newgidmap", child_pid, gidmap, logger=logger)
    logger.debug(f"newgidmap applied: {gidmap}")
