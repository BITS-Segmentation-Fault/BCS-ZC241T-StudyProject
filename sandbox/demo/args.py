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

    # sandbox tool args
    p.add_argument("--verbose", action="store_true")

    ns = p.parse_args(argv)

    config = Config(
        command=ns.command,
    )

    return Args(
        config=config,
        verbose=ns.verbose,
    )
