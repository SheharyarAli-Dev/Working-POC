from typing import Any, Literal
from uuid import uuid4
from datetime import datetime, timezone
from pydantic import BaseModel, Field


def now(): return datetime.now(timezone.utc).isoformat()

class RunContext(BaseModel):
    run_id: str=Field(default_factory=lambda:uuid4().hex[:12])
    created_at: str=Field(default_factory=now)
    title: str='ASENT assurance run'
    scenario: str='safe'
    mode: Literal['manual','watch','replay','research','gate']='manual'
    evidence_source: str='NORMAL SAFE CASE'
    agent_metadata: dict[str,Any]=Field(default_factory=dict)
    srs_digest: str=''
    approved_plan_digest: str=''
    policy_digest: str=''
    threat_repo_version: str=''
    threat_repo_digest: str=''
    baseline_commit: str=''
    candidate_snapshot: str=''
    candidate_workspace: str=''
    baseline_workspace: str=''
    changed_surfaces: dict[str,list[str]]=Field(default_factory=dict)
    module_evidence_ids: dict[str,str]=Field(default_factory=dict)
    applicable: list[str]=Field(default_factory=list)
    final_decision: Literal['ACCEPT','BLOCK','REVIEW']='REVIEW'
    reasons: list[str]=Field(default_factory=lambda:['Analysis pending'])
    lifecycle: str='CREATED'
    revision: int=0
    clean_commit: str | None=None
    clean_workspace: str | None=None
    error: str | None=None
    # Base .asent/ config frozen at creation (None: plain server run without one).
    config_digest: str | None=None
    config_source: str=''
    config_problems: list[str]=Field(default_factory=list)
    config_changed_in_head: bool=False
    coverage: dict[str,Any]=Field(default_factory=dict)
    gate: dict[str,Any]=Field(default_factory=dict)

class Evidence(BaseModel):
    evidence_id: str=Field(default_factory=lambda:uuid4().hex)
    run_id: str
    analyzer: str
    analyzer_version: str='1.0.0'
    threat_repo_version: str=''
    threat_repo_digest: str=''
    threat_module_digest: str=''
    candidate_snapshot: str
    input_hash: str
    status: str
    blocking: bool=False
    residual_uncertainty: list[str]=Field(default_factory=list)
    affected_files: list[str]=Field(default_factory=list)
    evidence_refs: list[str]=Field(default_factory=list)
    details: dict[str,Any]=Field(default_factory=dict)
    created_at: str=Field(default_factory=now)
    duration_ms: float=0
    reused_from: str | None=None
