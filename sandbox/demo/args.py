import argparse
from dataclasses import dataclass

from sandbox.demo.config import Config
from sandbox.demo.network import NetworkMode


@dataclass(frozen=True, slots=True)
class Args:
    config: Config
    verbose: bool


def parse_args(argv: list[str]) -> Args:
    p = argparse.ArgumentParser()

    # sandbox config args
    p.add_argument(
        "--network-mode",
        type=NetworkMode,
        default=NetworkMode.HOST,
        help='Set to "none" to disable internet access. Default: "host" (no network restrictions).',
    )
    p.add_argument(
        "command",
        nargs="+",
        help="Command to execute inside the sandbox.",
    )

    # sandbox tool args
    p.add_argument("--verbose", action="store_true")

    ns = p.parse_args(argv)

    config = Config(
        network_mode=ns.network_mode,
        command=ns.command,
    )

    return Args(
        config=config,
        verbose=ns.verbose,
    )
