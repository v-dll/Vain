"""Safe Nmap execution: validated targets, argument list (never a shell), timeout."""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path

from vain.errors import ScanError, TargetError

MAX_ADDRESSES = 65536  # a /16; larger needs --allow-large
MAX_TARGET_FILE_LINES = 10_000

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
_OCTET_RANGE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")
_PORTS = re.compile(r"^[0-9TU:,\-]+$")


def validate_target(token: str) -> tuple[str, int]:
    """Return (normalized token, number of addresses). Raises TargetError."""
    t = token.strip()
    if not t:
        raise TargetError("Empty target.")
    if t.startswith("-"):
        raise TargetError(f"Invalid target {t!r}: targets cannot start with '-'.")

    m = _OCTET_RANGE.match(t)
    if m:
        lo, hi = int(m.group(2)), int(m.group(3))
        try:
            ipaddress.ip_address(f"{m.group(1)}.{lo}")
            ipaddress.ip_address(f"{m.group(1)}.{hi}")
        except ValueError as exc:
            raise TargetError(f"Invalid range {t!r}.") from exc
        if lo > hi:
            raise TargetError(f"Invalid range {t!r}: start is greater than end.")
        return t, hi - lo + 1

    try:
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            return str(net), net.num_addresses
        ipaddress.ip_address(t)
        return t, 1
    except ValueError:
        pass

    if re.fullmatch(r"[\d.]+", t) or ":" in t:
        raise TargetError(f"Invalid IP address {t!r}.")
    if not _HOSTNAME.match(t):
        raise TargetError(f"Invalid target {t!r}: not an IP, CIDR block, range or hostname.")
    return t, 1


def resolve_targets(values: list[str], allow_large: bool = False) -> list[str]:
    """Expand --target values: comma lists and/or text files (one target per line)."""
    tokens: list[str] = []
    for value in values or []:
        if os.path.isfile(value):
            lines = Path(value).read_text(encoding="utf-8", errors="replace").splitlines()
            if len(lines) > MAX_TARGET_FILE_LINES:
                raise TargetError(f"Target file has more than {MAX_TARGET_FILE_LINES} lines.")
            for line in lines:
                line = line.split("#", 1)[0].strip()
                if line:
                    tokens.extend(p for p in line.replace(",", " ").split() if p)
        else:
            tokens.extend(p.strip() for p in value.split(",") if p.strip())

    if not tokens:
        raise TargetError("No targets given. Use --target IP|CIDR|hostname|file.txt")

    seen: dict[str, None] = {}
    total = 0
    for token in tokens:
        norm, count = validate_target(token)
        if norm not in seen:
            seen[norm] = None
            total += count
    if total > MAX_ADDRESSES and not allow_large:
        raise TargetError(
            f"{total:,} addresses is a very large scan (limit {MAX_ADDRESSES:,}). "
            "Pass --allow-large if you really mean it and are authorized."
        )
    return list(seen)


def find_nmap() -> str:
    path = shutil.which("nmap")
    if not path:
        raise ScanError(
            "nmap was not found in PATH. Install it (e.g. 'sudo apt install nmap', "
            "'brew install nmap') or use the Docker image, or analyze an existing scan with --xml."
        )
    return path


def build_command(
    targets: list[str],
    *,
    extra: list[str] | None = None,
    ports: str | None = None,
    timing: int = 4,
    os_detect: bool = False,
    no_ping: bool = False,
    nmap_path: str | None = None,
) -> list[str]:
    if not 0 <= timing <= 5:
        raise TargetError("--timing must be between 0 and 5.")
    cmd = [nmap_path or find_nmap(), "-oX", "-", "-sV", "--open", f"-T{timing}"]
    if ports:
        if not _PORTS.match(ports):
            raise TargetError(f"Invalid --ports value {ports!r} (example: 22,80,443 or 1-1024).")
        cmd += ["-p", ports]
    else:
        cmd += ["--top-ports", "1000"]
    if os_detect:
        cmd.append("-O")
    if no_ping:
        cmd.append("-Pn")
    cmd += list(extra or [])
    return cmd + targets


def run_nmap(cmd: list[str], timeout: int = 3600) -> str:
    """Run nmap and return its XML (stdout). No shell is ever involved."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f"nmap did not finish within {timeout} seconds and was stopped.") from exc
    except OSError as exc:
        raise ScanError(f"Could not start nmap: {exc}") from exc
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip()[-500:] or "no error output"
        raise ScanError(f"nmap exited with code {proc.returncode}: {tail}")
    return proc.stdout
