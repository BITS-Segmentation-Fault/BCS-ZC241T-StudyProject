from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Config:
    command: list[str]
    enable_network: bool = True