"""Small HTTP helper with retries/backoff, shared by plugins that call APIs.

Error messages deliberately never include the request URL: URLs can carry API
keys or webhook secrets, and messages end up in terminals and logs.
"""

from __future__ import annotations

import time
from typing import Any

import requests

from vain import __version__
from vain.errors import VainError

USER_AGENT = f"vain/{__version__} (defensive security tool)"
_RETRY_STATUS = {429, 500, 502, 503, 504}
_session: requests.Session | None = None


class HttpError(VainError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _get_session() -> requests.Session:
    global _session
    if _session is None:
        _session = requests.Session()
        _session.headers["User-Agent"] = USER_AGENT
    return _session


def _request(method: str, url: str, *, retries: int = 3, timeout: float = 20, **kwargs) -> requests.Response:
    last = "request failed"
    for attempt in range(retries + 1):
        try:
            resp = _get_session().request(method, url, timeout=timeout, **kwargs)
        except requests.RequestException as exc:
            last = f"network error ({type(exc).__name__})"
            resp = None
        else:
            if resp.status_code not in _RETRY_STATUS:
                return resp
            last = f"HTTP {resp.status_code}"
        if attempt < retries:
            delay = min(2 ** (attempt + 1), 30)
            if resp is not None and resp.headers.get("Retry-After", "").isdigit():
                delay = min(int(resp.headers["Retry-After"]), 60)
            time.sleep(delay)
    raise HttpError(f"{last} after {retries + 1} attempts")


def get_json(url: str, *, params: dict | str | None = None, headers: dict | None = None, timeout: float = 20) -> Any:
    resp = _request("GET", url, params=params, headers=headers, timeout=timeout)
    if resp.status_code >= 400:
        raise HttpError(f"HTTP {resp.status_code}", status=resp.status_code)
    try:
        return resp.json()
    except ValueError as exc:
        raise HttpError("response was not valid JSON") from exc


def post_json(url: str, payload: dict, *, timeout: float = 10, retries: int = 1) -> int:
    """POST JSON; returns the HTTP status. Raises HttpError on failure."""
    resp = _request("POST", url, json=payload, timeout=timeout, retries=retries)
    if resp.status_code >= 400:
        raise HttpError(f"HTTP {resp.status_code}", status=resp.status_code)
    return resp.status_code
