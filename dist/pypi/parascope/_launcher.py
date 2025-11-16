import os
import sys
from pathlib import Path


def find_binary() -> Path:
    here = Path(sys.argv[0]).resolve().parent

    candidates = [
        here / "rparascope",
        here / "rparascope.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c

    raise RuntimeError("could not locate parascope binary; installation may be broken")


def detect_ida_root() -> Path | None:
    idadir = os.environ.get("IDADIR")
    if idadir:
        p = Path(idadir)
        if p.is_dir():
            return p

    # Fallbacks matching idalib_build::link_path()
    if sys.platform == "darwin":
        default = Path("/Applications/IDA Professional 9.2.app/Contents/MacOS")
    elif sys.platform.startswith("linux"):
        default = Path(os.environ.get("HOME", "")) / "ida-pro-9.2"
    elif os.name == "nt":
        default = Path(r"C:\Program Files\IDA Professional 9.2")
    else:
        return None

    return default if default.is_dir() else None


def prepend_env_path(var: str, directory: Path) -> None:
    old = os.environ.get(var, "")
    if old:
        os.environ[var] = str(directory) + os.pathsep + old
    else:
        os.environ[var] = str(directory)


def configure_loader_paths(ida_root: Path) -> None:
    if sys.platform.startswith("linux"):
        prepend_env_path("LD_LIBRARY_PATH", ida_root)
    elif sys.platform == "darwin":
        prepend_env_path("DYLD_LIBRARY_PATH", ida_root)
    elif os.name == "nt":
        prepend_env_path("PATH", ida_root)
    else:
        pass


def main() -> None:
    bin_path = find_binary()
    ida_root = detect_ida_root()
    if ida_root is None:
        sys.stderr.write(
            "[parascope] could not auto-detect IDA installation; "
            "set `IDADIR` if you see loader errors.\n"
        )
    else:
        configure_loader_paths(ida_root)

    os.execv(str(bin_path), [str(bin_path), *sys.argv[1:]])
