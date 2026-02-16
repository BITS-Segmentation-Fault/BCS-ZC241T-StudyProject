from pathlib import Path


def read_text(path: Path | str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        return "<missing>"
    except PermissionError as e:
        return f"<permission denied: {e}>"
    except OSError as e:
        return f"<error: {e}>"


def write_text(path: Path | str, data: str) -> None:
    Path(path).write_text(data, encoding="utf-8")
