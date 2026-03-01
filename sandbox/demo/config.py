from dataclasses import dataclass

from sandbox.demo.network import NetworkMode


@dataclass(frozen=True, slots=True)
class Config:
    network_mode: NetworkMode
    command: list[str]
