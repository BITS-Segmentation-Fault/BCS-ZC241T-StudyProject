import argparse
from dataclasses import dataclass

from sandbox.demo.config import Config


@dataclass(frozen=True, slots=True)
class Args:
    config: Config
    verbose: bool


def parse_args(argv: list[str]) -> Args:
    p = argparse.ArgumentParser()

    # sandbox config args
    p.add_argument("command", nargs="+")

    # network toggle
    p.add_argument(
        "--no-net",
        action="store_true",
        help="Disable internet by unsharing network namespace",
    )

    # sandbox tool args
    p.add_argument("--verbose", action="store_true")

    ns = p.parse_args(argv)

    config = Config(
        command=ns.command,
        enable_network=not ns.no_net,
    )

    return Args(
        config=config,
        verbose=ns.verbose,
    )