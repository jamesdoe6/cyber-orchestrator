"""Pydantic request/response models."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from .models import Mode, RunStatus, Severity


class TargetEntry(BaseModel):
    type: str = Field(description="ip | cidr | host | domain | url | ssid")
    value: str


class EngagementCreate(BaseModel):
    name: str
    mode: Mode
    operator: str


class EngagementOut(BaseModel):
    id: int
    name: str
    mode: Mode
    operator: str
    created_at: datetime
    closed_at: datetime | None
    has_authorization: bool

    class Config:
        from_attributes = True


class AuthorizationIn(BaseModel):
    authorization_ref: str
    authorizing_party: str
    targets: list[TargetEntry]
    valid_from: datetime
    valid_until: datetime
    notes: str = ""
    accept: bool = Field(default=True, description="Mark the authorization as accepted/signed.")


class AuthorizationOut(BaseModel):
    id: int
    authorization_ref: str
    authorizing_party: str
    targets: list[dict]
    valid_from: datetime
    valid_until: datetime
    accepted: bool
    accepted_at: datetime | None
    notes: str

    class Config:
        from_attributes = True


class RunCreate(BaseModel):
    plugin: str
    params: dict = Field(default_factory=dict)


class FindingOut(BaseModel):
    id: int
    title: str
    description: str
    severity: Severity
    cvss: float | None
    asset: str
    attack_technique: str
    remediation: str
    evidence: dict

    class Config:
        from_attributes = True


class RunOut(BaseModel):
    id: int
    plugin: str
    target: str
    status: RunStatus
    command: str
    attack_techniques: list
    exit_code: int | None
    error: str
    parsed: dict
    findings: list[FindingOut] = []

    class Config:
        from_attributes = True
