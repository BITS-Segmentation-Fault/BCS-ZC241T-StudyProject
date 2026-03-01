import logging
import os

from sandbox.demo.fs import read_text
from sandbox.demo.utils import select_lines_with_prefix

# proc status keys to log in debug mode
STATUS_KEYS: tuple[str, ...] = ("Uid:", "Gid:", "Groups:", "CapEff:", "NSpid:")


def log_identity(
    logger: logging.Logger, label: str, host_uid: int, host_gid: int
) -> None:
    uid, euid = os.getuid(), os.geteuid()
    gid, egid = os.getgid(), os.getegid()

    ruid, reuid, suid = os.getresuid()
    rgid, regid, sgid = os.getresgid()

    logger.debug(f"=== {label} ===")
    logger.debug(f"host: uid={host_uid},gid={host_gid}")
    logger.debug(f"self: uid={uid},euid={euid},gid={gid},egid={egid}")
    logger.debug(f"self: resuid={ruid},{reuid},{suid} resgid={rgid},{regid},{sgid}")

    uid_map = read_text("/proc/self/uid_map")
    gid_map = read_text("/proc/self/gid_map")
    logger.debug(f"/proc/self/uid_map:\n{uid_map}")
    logger.debug(f"/proc/self/gid_map:\n{gid_map}")

    status = read_text("/proc/self/status")
    for line in select_lines_with_prefix(status, STATUS_KEYS):
        logger.debug(line)
