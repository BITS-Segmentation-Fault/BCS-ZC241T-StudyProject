import logging
import os

from sandbox.demo.common import ACK_BYTE, READY_BYTE
from sandbox.demo.config import Config
from sandbox.demo.diag import log_identity
from sandbox.demo.utils import flush_logs


def child(
    cfg: Config,
    p2c_r: int,
    c2p_w: int,
    host_uid: int,
    host_gid: int,
) -> int:
    logger = logging.getLogger("sandbox_demo.child")

    try:
        os.setgroups([])
    except Exception:
        logger.debug("os.setgroups([]) not permitted; continuing")

    logger.info("child starting before unshare()")
    log_identity(logger, "child (before unshare)", host_uid, host_gid)
    try:
        os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)
        logger.info("unshare(CLONE_NEWUSER) success")
    except OSError as e:
        logger.error(f"unshare(CLONE_NEWUSER) fail: {e}")
        return 1

    # tell parent that we are ready
    os.write(c2p_w, READY_BYTE)
    logger.debug("signaled ready to parent")

    # wait for ACK
    ack = os.read(p2c_r, 1)
    if ack != ACK_BYTE:
        logger.error("did not receive mapping ACK from parent; aborting")
        return 1

    # become root inside namespace
    try:
        os.setresgid(0, 0, 0)
    except PermissionError as e:
        logger.warning(f"setresgid(0) fail: {e}; continuing")
    try:
        os.setresuid(0, 0, 0)
    except PermissionError as e:
        logger.warning(f"setresgid(0) fail: {e}; continuing")

    logger.info("child is now root inside the user namespace")
    log_identity(logger, "child (after mapping + setuid(0))", host_uid, host_gid)

    # normal behavior: execute target program
    logger.info(f"exec: {cfg.command}")
    flush_logs()

    try:
        os.execvp(cfg.command[0], cfg.command)
    except Exception as e:
        logger.error(f"failed to execute target program: {e}")
        return 1

    # unreachable
    return 0
# Test change