import logging
from typing import Iterable


def setup_logging(level: int | str) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s pid=%(process)d %(name)s: %(message)s",
    )


def flush_logs() -> None:
    root = logging.getLogger()
    for h in root.handlers:
        try:
            h.flush
        except Exception:
            continue


def select_lines_with_prefix(text: str, prefix: Iterable[str]) -> list[str]:
    p = tuple(prefix)
    return [line for line in text.splitlines() if line.startswith(prefix)]
