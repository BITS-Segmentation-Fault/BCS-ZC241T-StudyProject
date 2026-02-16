import logging
import os
import signal
from pathlib import Path

from sandbox.demo.child import child
from sandbox.demo.common import ACK_BYTE, READY_BYTE
from sandbox.demo.config import Config
from sandbox.demo.diag import log_identity
from sandbox.demo.fs import write_text


def write_id_maps(
    child_pid: int, host_uid: int, host_gid: int, *, logger: logging.Logger
) -> None:
    proc = Path(f"/proc/{child_pid}")
    uid_map_path = proc / "uid_map"
    gid_map_path = proc / "gid_map"
    setgroups_path = proc / "setgroups"

    try:
        if setgroups_path.exists():
            write_text(setgroups_path, "deny\n")
            logger.debug(f"wrote {setgroups_path}: deny")
    except OSError as e:
        logger.warning(f"could not write {setgroups_path}: {e} (gid_map may fail)")

    uid_map = f"0 {host_uid} 1\n"
    gid_map = f"0 {host_gid} 1\n"

    write_text(uid_map_path, uid_map)
    logger.debug(f"wrote {uid_map_path}:\n{uid_map}")

    try:
        write_text(gid_map_path, gid_map)
        logger.debug(f"wrote {gid_map_path}:\n{gid_map}")
    except OSError as e:
        logger.warning(f"could not write {gid_map_path}: {e} (groups may be limited)")


def parent(
    cfg: Config,
    *,
    logger: logging.Logger,
) -> int:
    host_uid = os.getuid()
    host_gid = os.getgid()

    logger.info(f"host: uid={host_uid},gid={host_gid}")
    log_identity(logger, "parent (host namespace)", host_uid, host_gid)

    c2p_r, c2p_w = os.pipe()
    p2c_r, p2c_w = os.pipe()

    pid = os.fork()
    if pid == 0:
        # child
        os.close(c2p_r)
        os.close(p2c_w)
        rc = child(
            cfg,
            p2c_r,
            c2p_w,
            host_uid,
            host_gid,
        )
        os._exit(rc)

    # parent
    os.close(c2p_w)
    os.close(p2c_r)

    # wait for child readiness
    b = os.read(c2p_r, 1)
    if b != READY_BYTE:
        logger.error("child did not signal readiness; aborting")
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        return 1

    logger.debug(f"child ready; writing uid/gid maps for pid={pid}")
    try:
        write_id_maps(pid, host_uid, host_gid, logger=logger)
    except OSError as e:
        logger.error(f"failed to write uid/gid maps: {e}")
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        return 1

    # ACK child
    os.write(p2c_w, ACK_BYTE)

    # normal behavior: wait for child and exit
    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)

    logger.info(f"child exit code: {code}")
    return code
