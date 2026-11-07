"""Schema of a project's `.asent/` folder (docs/asent-config.md).

Three documents have a fixed shape and are pydantic models here:

    .asent/config.json              AsentConfig       which modules apply and where their inputs are
    .asent/satra/contract.json      SatraContract     the security contract SATRA enforces
    .asent/sable/obligations.json   SableObligations  the infrastructure obligations SABLE enforces

`.asent/cavr/policy.json` keeps the format CAVR already reads (`requirement_gate`,
`capability_contract`); the loader checks it with those modules' own functions.

Every model forbids unknown keys and is strict (no "403" for 403, no "yes" for true): a value
that is not exactly what the schema says is a problem, never a guess. All paths are relative,
use "/", contain no "..", and never name `.git`; paths into the project also never name `.asent`.

`python -m backend.project_config --write docs` regenerates the committed JSON Schemas;
`tests/test_project_config.py` fails when they drift from these models.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Annotated, Literal, Optional

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

SCHEMA_VERSION = 1
MODULE_NAMES = ("CAVR", "SATRA", "SABLE")
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _safe_relative(value: str, *, in_project: bool) -> str:
    """`value` as a normalised relative POSIX path, or ValueError when it could leave its root."""
    if not value or not value.strip():
        raise ValueError("path must be non-empty text")
    if "\\" in value or "\x00" in value:
        raise ValueError('path must use "/" and contain no NUL')
    windows = PureWindowsPath(value)
    if PurePosixPath(value).is_absolute() or windows.is_absolute() or windows.drive:
        raise ValueError("path must be relative")
    parts = PurePosixPath(value).parts
    if not parts:
        raise ValueError("path must name a file or directory")
    if ".." in parts:
        raise ValueError('path must not contain ".."')
    if ".git" in parts:
        raise ValueError('path must not name ".git"')
    if in_project and parts[0] == ".asent":
        raise ValueError('a project path must not point into ".asent"')
    return PurePosixPath(*parts).as_posix()


AsentPath = Annotated[str, AfterValidator(lambda v: _safe_relative(v, in_project=False))]
ProjectPath = Annotated[str, AfterValidator(lambda v: _safe_relative(v, in_project=True))]
Text = Annotated[str, Field(min_length=1), AfterValidator(lambda v: _non_blank(v))]


def _non_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be blank")
    return value


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


# --- .asent/config.json ---------------------------------------------------------------------------

class _Module(_Model):
    enabled: bool = Field(description="false switches the module off; the report then says it was not assessed")
    reason: Optional[str] = Field(None, description="required when enabled is false")

    @model_validator(mode="after")
    def _disabled_needs_reason(self):
        if not self.enabled and not (self.reason or "").strip():
            raise ValueError('a disabled module needs a non-empty "reason"')
        return self


class CavrModule(_Module):
    policy: AsentPath = Field("cavr/policy.json", description="CAVR policy inside .asent/")
    requirements_files: list[ProjectPath] = Field(default_factory=lambda: ["requirements.txt"], min_length=1,
                                                  description="pip requirements files in the project")
    verify: Literal["all", "changed"] = Field("all", description="all pins in head, or only the base->head edit")
    import_aliases: dict[Text, list[Text]] = Field(default_factory=dict,
                                                   description="distribution name -> import names, when they differ")
    source_dirs: list[ProjectPath] = Field(default_factory=list, description="where call sites are read; empty = whole project")


class SatraModule(_Module):
    contract: AsentPath = Field("satra/contract.json", description="SATRA security contract inside .asent/")
    trusted_tests: AsentPath = Field("satra/trusted_tests", description="trusted pytest directory inside .asent/")
    pytest_ini: Optional[AsentPath] = Field(None, description="pytest.ini for the trusted tests, inside .asent/")
    source_dirs: list[ProjectPath] = Field(default_factory=list, description="application code; empty = whole project")
    project_security_tests: Optional[ProjectPath] = Field(None, description="the project's own security test file, checked for a weakened oracle")


class SableModule(_Module):
    terraform_dirs: list[ProjectPath] = Field(default_factory=lambda: ["infra"], min_length=1,
                                              description="Terraform directories in the project")
    obligations: AsentPath = Field("sable/obligations.json", description="SABLE obligations inside .asent/")


class Modules(_Model):
    CAVR: Optional[CavrModule] = None
    SATRA: Optional[SatraModule] = None
    SABLE: Optional[SableModule] = None


class Project(_Model):
    name: str = Field(min_length=1, max_length=100)


class AsentConfig(_Model):
    """`.asent/config.json`."""
    # Not Literal[1]: Literal compares by ==, so true and 1.0 would pass; a strict int does not.
    schema_version: int = Field(ge=SCHEMA_VERSION, le=SCHEMA_VERSION, description="must be 1")
    project: Project
    modules: Modules
    starter: bool = Field(False, alias="_starter",
                          description="written as true by `asent init`; a config with true is refused until a person reviews it")


# --- .asent/satra/contract.json -------------------------------------------------------------------

def _target(value: str) -> str:
    path, sep, function = value.partition("::")
    if not sep or "::" in function or not IDENTIFIER.match(function):
        raise ValueError('target must be "<file>::<function>"')
    return _safe_relative(path, in_project=True) + "::" + function


class Counterfactual(_Model):
    operator: Literal["RETURN_TRUE"] = Field(description="replace the target function's body with `return True`")
    target: Annotated[str, AfterValidator(_target)]


class SatraContract(_Model):
    """`.asent/satra/contract.json`."""
    rule_id: Text
    version: int = Field(1, ge=1)
    route: Text = Field(description='e.g. "GET /invoices/{invoice_id}"')
    expected_status: int = Field(ge=100, le=599, description="status a denied request must get")
    authority_sources: list[Text] = Field(min_length=1, description="where the requirement comes from")
    preconditions: list[Text] = Field(default_factory=list)
    scope: list[ProjectPath] = Field(min_length=1, description="files the contract is about")
    counterfactual: Counterfactual
    subject: Optional[str] = None
    action: Optional[str] = None
    resource: Optional[str] = None
    state_effect: Optional[str] = None
    description: Optional[str] = None


# --- .asent/sable/obligations.json ----------------------------------------------------------------

class Obligation(_Model):
    id: Text
    principal: Text = Field(description='Terraform address, e.g. "aws_iam_role.app"')
    protected_asset: Text = Field(description='Terraform address, e.g. "aws_s3_bucket.invoice_data"')
    actions: list[Text] = Field(min_length=1)
    scope: Text = "objects"
    minimum_score: int = Field(6, ge=0)
    margin: int = Field(3, ge=0)


class SableObligations(_Model):
    """`.asent/sable/obligations.json`."""
    obligations: list[Obligation] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_ids(self):
        ids = [item.id for item in self.obligations]
        if len(ids) != len(set(ids)):
            raise ValueError("obligation ids must be unique")
        return self


# --- documented JSON Schemas ----------------------------------------------------------------------

SCHEMA_FILES = {
    "asent-config.schema.json": (AsentConfig, "ASENT project configuration (.asent/config.json)"),
    "asent-satra-contract.schema.json": (SatraContract, "ASENT SATRA contract (.asent/satra/contract.json)"),
    "asent-sable-obligations.schema.json": (SableObligations, "ASENT SABLE obligations (.asent/sable/obligations.json)"),
}


def export_schemas() -> dict[str, dict]:
    """{file name: JSON Schema} for every document above, as committed in docs/."""
    out = {}
    for name, (model, title) in SCHEMA_FILES.items():
        schema = model.model_json_schema(by_alias=True)
        schema["title"] = title
        out[name] = {"$schema": "https://json-schema.org/draft/2020-12/schema", **schema}
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Write the ASENT .asent/ JSON Schemas")
    parser.add_argument("--write", metavar="DIR", required=True)
    args = parser.parse_args(argv)
    for name, schema in export_schemas().items():
        target = Path(args.write) / name
        target.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
        print(target)
    return 0

