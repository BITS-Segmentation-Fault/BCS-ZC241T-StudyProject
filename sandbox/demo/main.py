import logging
import sys

from sandbox.demo.args import parse_args
from sandbox.demo.parent import parent
from sandbox.demo.utils import setup_logging


def main(argv: list[str]) -> int:
    print(sys.version)
    args = parse_args(argv)

    setup_logging(logging.DEBUG if args.verbose else logging.INFO)

    logger = logging.getLogger("sandbox_demo")

    if not sys.platform.startswith("linux"):
        logger.error(f"unsupported on platform: {sys.platform}")
        return 2

    logger.debug(f"args: {args}")

    return parent(args.config, logger=logger)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
