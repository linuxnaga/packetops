"""Request bodies for the REST API (responses are the service-layer documents)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DevLogin(Body):
    email: str = Field(max_length=200)


class AnalyzeRequest(Body):
    force: bool = False


class FindingUpdate(Body):
    status: Literal["open", "investigating", "confirmed", "dismissed", "resolved"] | None = None
    assignee: str | None = Field(default=None, max_length=64)
    note: str | None = Field(default=None, max_length=5000)


class F5ConfigImport(Body):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=500)
    config: dict | None = None
    text: str | None = Field(default=None, max_length=2 * 1024 * 1024, description="tmsh 'list' / bigip.conf text")
    replace: bool = False


class CorrelationRequest(Body):
    client_capture_id: str = Field(pattern=r"^cap_[0-9a-f]{20}$")
    server_capture_id: str | None = Field(default=None, pattern=r"^cap_[0-9a-f]{20}$")
    config_id: str | None = Field(default=None, pattern=r"^f5c_[0-9a-f]{20}$")


class ConsoleExecute(Body):
    line: str = Field(max_length=512)


class ConsoleComplete(Body):
    line: str = Field(max_length=512)


class MissionSubmit(Body):
    objective: int = Field(ge=1, le=20)
    answer: str = Field(min_length=1, max_length=200)


class ReportCreate(Body):
    capture_id: str = Field(pattern=r"^cap_[0-9a-f]{20}$")
    format: Literal["html", "pdf", "json"] = "html"


class InvestigationCreate(Body):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=5000)
    capture_ids: list[str] = Field(default_factory=list, max_length=50)
    finding_ids: list[str] = Field(default_factory=list, max_length=500)
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None


class InvestigationUpdate(Body):
    status: Literal["open", "in_progress", "resolved", "closed"] | None = None
    title: str | None = Field(default=None, max_length=200)
    add_capture_ids: list[str] = Field(default_factory=list, max_length=50)
    add_finding_ids: list[str] = Field(default_factory=list, max_length=500)
    note: str | None = Field(default=None, max_length=5000)
