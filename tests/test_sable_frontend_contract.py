from pathlib import Path


def test_not_applicable_sable_evidence_is_not_shown_as_acceptable():
    component = (
        Path(__file__).resolve().parents[1]
        / "frontend"
        / "src"
        / "components"
        / "RunWorkflowModule.tsx"
    )
    source = component.read_text(encoding="utf-8")

    assert "sableStatus === 'PRESERVED' ? 'PRESERVED -> ACCEPTABLE'" in source
    assert "sableStatus === 'REGRESSED' ? 'REGRESSED -> BLOCKING'" in source
    assert "`${sableStatus} -> REVIEW`" in source
    assert "sableStatus === 'NOT_APPLICABLE'" not in source
