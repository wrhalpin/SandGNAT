"""VirusTotal v3 hash-lookup client.

We only ever ask VT "have you seen this hash?" — never upload bytes. Uploading
would leak our sample corpus to a third party and defeats the point of running
our own sandbox. The intake pipeline uses the verdict as a prioritisation
signal, not as a gate.

The client degrades gracefully: missing API key, network error, 4xx, and 5xx
all resolve to a `VTVerdict` with `verdict='unknown'` or `verdict='error'`
instead of raising. Intake must never fail because VT is flaky.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import requests

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class VTVerdict:
    """Summary of VirusTotal knowledge about a file hash.

    `verdict` is one of:
      * 'malicious'   — at least one AV flagged this
      * 'suspicious'  — at least one AV marked suspicious, none malicious
      * 'harmless'    — AVs saw it and none flagged anything
      * 'undetected'  — VT has the file but no engine has an opinion
      * 'unknown'     — VT has never seen this hash
      * 'error'       — we couldn't reach VT / got a malformed response
    """

    verdict: str
    detection_count: int | None = None
    total_engines: int | None = None
    last_seen: datetime | None = None
    error: str | None = None

    @property
    def is_known_malicious(self) -> bool:
        return self.verdict == "malicious" and (self.detection_count or 0) > 0


class VTClient:
    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = "https://www.virustotal.com/api/v3",
        timeout_seconds: float = 10.0,
        session: requests.Session | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._session = session or requests.Session()

    @property
    def enabled(self) -> bool:
        return bool(self._api_key)

    def lookup_hash(self, sha256: str) -> VTVerdict:
        """Fetch VT's summary for `sha256`. Never raises."""
        if not self.enabled:
            return VTVerdict(verdict="unknown")
        url = f"{self._base_url}/files/{sha256}"
        try:
            resp = self._session.get(
                url,
                headers={"x-apikey": self._api_key, "accept": "application/json"},
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            log.warning("VT lookup failed for %s: %s", sha256, exc)
            return VTVerdict(verdict="error", error=str(exc))

        if resp.status_code == 404:
            return VTVerdict(verdict="unknown")
        if resp.status_code == 401:
            log.error("VT rejected API key (401)")
            return VTVerdict(verdict="error", error="unauthorized")
        if resp.status_code >= 400:
            return VTVerdict(verdict="error", error=f"http {resp.status_code}")

        try:
            payload = resp.json()
        except ValueError as exc:
            return VTVerdict(verdict="error", error=f"bad json: {exc}")

        return _verdict_from_payload(payload)


def _verdict_from_payload(payload: dict) -> VTVerdict:
    try:
        attrs = payload["data"]["attributes"]
    except (KeyError, TypeError):
        return VTVerdict(verdict="error", error="missing attributes")

    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    total = malicious + suspicious + harmless + undetected

    if malicious > 0:
        verdict = "malicious"
    elif suspicious > 0:
        verdict = "suspicious"
    elif total > 0 and harmless > 0 and undetected == total - harmless:
        verdict = "harmless"
    elif total > 0:
        verdict = "undetected"
    else:
        verdict = "unknown"

    last_seen_epoch = attrs.get("last_analysis_date") or attrs.get("last_submission_date")
    last_seen = (
        datetime.fromtimestamp(int(last_seen_epoch), tz=timezone.utc)
        if last_seen_epoch
        else None
    )
    return VTVerdict(
        verdict=verdict,
        detection_count=malicious + suspicious,
        total_engines=total or None,
        last_seen=last_seen,
    )
