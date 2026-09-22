"""Strict versioned API contracts used by the React client."""

from datetime import datetime
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StrictStr


class StrictApiModel(BaseModel):
    """Reject implicit coercion and undocumented fields at the API boundary."""

    model_config = ConfigDict(extra="forbid", strict=True)


class LoginRequest(StrictApiModel):
    token: StrictStr = Field(min_length=1, max_length=4096)


class AuthState(StrictApiModel):
    required: bool
    authenticated: bool
    expires_at: Optional[datetime] = None


class ProductMetadata(StrictApiModel):
    name: str
    version: str
    description: Optional[str] = None


class RuntimeMetadata(StrictApiModel):
    production: bool
    demo_mode: bool


class CapabilityMetadata(StrictApiModel):
    scanner: bool
    database: bool
    dns_fix: bool
    pdf: bool
    monitoring_enabled: bool
    automatic_remediation: bool


class OperatorMetadata(StrictApiModel):
    org_name: str


class BootstrapResponse(StrictApiModel):
    product: ProductMetadata
    auth: AuthState
    runtime: RuntimeMetadata
    capabilities: CapabilityMetadata
    operator: OperatorMetadata


Grade = Literal["A+", "A", "B", "C", "D", "F"]


class ManagedDomainResponse(StrictApiModel):
    id: int
    domain: str
    added_at: Optional[datetime] = None
    is_active: bool
    last_scan_at: Optional[datetime] = None
    last_grade: Optional[Grade] = None
    last_score: Optional[int] = Field(default=None, ge=0, le=100)
    previous_grade: Optional[Grade] = None
    previous_score: Optional[int] = Field(default=None, ge=0, le=100)
    notes: str


class AlertResponse(StrictApiModel):
    id: int
    domain: str
    alert_type: str
    severity: str
    message: str
    details: str
    created_at: Optional[datetime] = None
    acknowledged: bool
    acknowledged_at: Optional[datetime] = None


class ScoreStatistics(StrictApiModel):
    avg_score: Optional[float] = None
    min_score: Optional[int] = None
    max_score: Optional[int] = None


class DashboardStats(StrictApiModel):
    total_scans: int = Field(ge=0)
    unique_domains: int = Field(ge=0)
    total_results: int = Field(ge=0)
    score_stats: ScoreStatistics
    severity_distribution: Dict[str, int]
    total_domains: int = Field(ge=0)
    average_score: int = Field(ge=0, le=100)
    passing_domains: int = Field(ge=0)
    failing_domains: int = Field(ge=0)
    grade_distribution: Dict[str, int]
    alert_count: int = Field(ge=0)


class DashboardSettings(StrictApiModel):
    monitor_interval_hours: int
    monitoring_enabled: bool
    automatic_remediation: bool


class DashboardResponse(StrictApiModel):
    stats: DashboardStats
    domains: List[ManagedDomainResponse]
    alerts: List[AlertResponse]
    settings: DashboardSettings
