"""Scope enforcement — the blocking legal guardrail.

A plugin declares a *privilege level*:

* ``passive``   — no packets to the target (pure OSINT, local log parsing).
* ``active``    — touches the target but non-destructive (port scan, banner).
* ``offensive`` — exploitation / credential attacks / injection / wifi, etc.

``check()`` is the single chokepoint every run goes through. It refuses — with
a machine-readable reason — when:

* the global ``offensive_enabled`` kill-switch is off and the plugin is offensive;
* the engagement has no accepted authorization (for active/offensive levels);
* the current time is outside the authorization validity window;
* the requested target is not covered by the authorized perimeter.

Passive plugins are allowed without a target match but are still audited.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..config import settings
from ..models import Engagement, ScopeAuthorization

PASSIVE = "passive"
ACTIVE = "active"
OFFENSIVE = "offensive"
_LEVELS = {PASSIVE: 0, ACTIVE: 1, OFFENSIVE: 2}


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    matched: str | None = None   # which authorized entry matched


def _host_of(value: str) -> str:
    value = value.strip()
    if "://" in value:
        return (urlparse(value).hostname or "").lower()
    return value.split("/")[0].split(":")[0].lower()


def _ip_in(target_ip: ipaddress._BaseAddress, entry_value: str) -> bool:
    try:
        if "/" in entry_value:
            return target_ip in ipaddress.ip_network(entry_value, strict=False)
        return target_ip == ipaddress.ip_address(entry_value)
    except ValueError:
        return False


def _target_in_scope(target: str, targets: list[dict]) -> str | None:
    """Return the matching authorized entry's value, or None."""
    if not target:
        return None
    t = target.strip()

    # Try to interpret the target as an IP for IP/CIDR matching.
    parsed_ip = None
    try:
        parsed_ip = ipaddress.ip_address(_host_of(t))
    except ValueError:
        parsed_ip = None

    thost = _host_of(t)
    for entry in targets:
        etype = (entry.get("type") or "").lower()
        evalue = (entry.get("value") or "").strip()
        if not evalue:
            continue
        if etype in ("ip", "cidr") and parsed_ip is not None and _ip_in(parsed_ip, evalue):
            return evalue
        if etype in ("host", "domain", "url"):
            ehost = _host_of(evalue)
            # exact host or subdomain of an authorized domain
            if thost == ehost or thost.endswith("." + ehost):
                return evalue
        if etype == "ssid" and t == evalue:
            return evalue
    return None


def check(
    engagement: Engagement,
    *,
    privilege: str,
    target: str = "",
    now: datetime | None = None,
) -> ScopeDecision:
    level = _LEVELS.get(privilege, _LEVELS[OFFENSIVE])
    now = now or datetime.now(timezone.utc)

    if level >= _LEVELS[OFFENSIVE] and not settings.offensive_enabled:
        return ScopeDecision(False, "offensive_disabled: global kill-switch is off")

    # Passive work needs no perimeter match, but is still blocked if the
    # engagement was explicitly closed.
    if engagement.closed_at is not None:
        return ScopeDecision(False, "engagement_closed")

    if level <= _LEVELS[PASSIVE] or not settings.enforce_scope:
        return ScopeDecision(True, "allowed")

    auth: ScopeAuthorization | None = engagement.authorization
    if auth is None or not auth.accepted:
        return ScopeDecision(False, "no_authorization: declare and accept a scope first")

    vf = auth.valid_from
    vu = auth.valid_until
    if vf.tzinfo is None:
        vf = vf.replace(tzinfo=timezone.utc)
    if vu.tzinfo is None:
        vu = vu.replace(tzinfo=timezone.utc)
    if not (vf <= now <= vu):
        return ScopeDecision(False, f"outside_window: authorized {vf.date()}..{vu.date()}")

    matched = _target_in_scope(target, auth.targets)
    if matched is None:
        return ScopeDecision(False, f"target_out_of_scope: '{target}' not in authorized perimeter")

    return ScopeDecision(True, "allowed", matched=matched)
