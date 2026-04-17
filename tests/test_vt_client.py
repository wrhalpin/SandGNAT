"""Tests for the VirusTotal client.

The client is stubbed with a fake `requests.Session` — no network access.
We care about the verdict-classification mapping and the error-handling
contract (never raise, always return a VTVerdict).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
import requests

from orchestrator.vt_client import VTClient, VTVerdict


@dataclass
class _StubResponse:
    status_code: int
    payload: dict | None = None
    raise_json: bool = False

    def json(self) -> Any:
        if self.raise_json:
            raise ValueError("bad json")
        return self.payload


class _StubSession:
    def __init__(self, response: _StubResponse | Exception) -> None:
        self._response = response
        self.calls: list[tuple[str, dict]] = []

    def get(self, url: str, **kwargs: Any):  # type: ignore[no-untyped-def]
        self.calls.append((url, kwargs))
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def _vt(session: _StubSession) -> VTClient:
    return VTClient(api_key="k", session=session)  # type: ignore[arg-type]


def test_disabled_when_no_api_key() -> None:
    client = VTClient(api_key="")
    assert client.enabled is False
    assert client.lookup_hash("a" * 64).verdict == "unknown"


def test_malicious_verdict_from_stats() -> None:
    session = _StubSession(
        _StubResponse(
            status_code=200,
            payload={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 42,
                            "suspicious": 3,
                            "harmless": 10,
                            "undetected": 15,
                        },
                        "last_analysis_date": 1700000000,
                    }
                }
            },
        )
    )
    verdict = _vt(session).lookup_hash("f" * 64)
    assert verdict.verdict == "malicious"
    assert verdict.detection_count == 45
    assert verdict.total_engines == 70
    assert verdict.last_seen is not None
    assert verdict.is_known_malicious is True


def test_suspicious_when_only_suspicious_hits() -> None:
    session = _StubSession(
        _StubResponse(
            status_code=200,
            payload={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 5,
                            "harmless": 0,
                            "undetected": 60,
                        }
                    }
                }
            },
        )
    )
    verdict = _vt(session).lookup_hash("a" * 64)
    assert verdict.verdict == "suspicious"
    assert verdict.is_known_malicious is False


def test_undetected_when_vt_has_file_but_no_hits() -> None:
    session = _StubSession(
        _StubResponse(
            status_code=200,
            payload={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 0,
                            "undetected": 70,
                        }
                    }
                }
            },
        )
    )
    verdict = _vt(session).lookup_hash("a" * 64)
    assert verdict.verdict == "undetected"


def test_unknown_on_404() -> None:
    session = _StubSession(_StubResponse(status_code=404))
    assert _vt(session).lookup_hash("a" * 64).verdict == "unknown"


def test_error_on_401() -> None:
    session = _StubSession(_StubResponse(status_code=401))
    v = _vt(session).lookup_hash("a" * 64)
    assert v.verdict == "error"
    assert v.error == "unauthorized"


def test_error_on_malformed_payload() -> None:
    session = _StubSession(
        _StubResponse(status_code=200, payload={"data": {"unexpected": "shape"}})
    )
    v = _vt(session).lookup_hash("a" * 64)
    assert v.verdict == "error"


def test_error_on_request_exception_never_raises() -> None:
    session = _StubSession(requests.ConnectionError("dns failure"))
    v = _vt(session).lookup_hash("a" * 64)
    assert v.verdict == "error"
    assert "dns failure" in (v.error or "")


def test_sends_api_key_header() -> None:
    session = _StubSession(_StubResponse(status_code=404))
    _vt(session).lookup_hash("deadbeef" * 8)
    assert session.calls
    url, kwargs = session.calls[0]
    assert url.endswith("/files/" + "deadbeef" * 8)
    assert kwargs["headers"]["x-apikey"] == "k"
