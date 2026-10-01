"""Tests for CISA CSF alignment module."""

import pytest
from src.grid.cisa_compliance import (
    CSFFunction,
    ControlStatus,
    Control,
    CSFControlCatalog,
    ControlAssessment,
    GapAnalysis,
    CISAComplianceReport,
    Gap,
)


# ── CSFFunction / ControlStatus enums ──────────────────────────────────────

def test_csf_function_enum_has_six_functions():
    """CISA CSF defines exactly six functions."""
    assert len(CSFFunction) == 6
    names = {f.name for f in CSFFunction}
    assert names == {"GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"}


def test_control_status_enum_has_three_levels():
    """Control status has three implementation levels."""
    assert len(ControlStatus) == 3
    names = {s.name for s in ControlStatus}
    assert names == {"NOT_IMPLEMENTED", "PARTIALLY_IMPLEMENTED", "IMPLEMENTED"}


def test_control_status_ordering():
    """Status values are ordered by implementation maturity."""
    assert ControlStatus.NOT_IMPLEMENTED.value < ControlStatus.PARTIALLY_IMPLEMENTED.value
    assert ControlStatus.PARTIALLY_IMPLEMENTED.value < ControlStatus.IMPLEMENTED.value


# ── CSFControlCatalog ─────────────────────────────────────────────────────

def test_catalog_contains_all_six_functions():
    """Catalog covers every CSF function."""
    catalog = CSFControlCatalog()
    controls = catalog.all_controls()
    functions_covered = {c.function for c in controls}
    assert functions_covered == set(CSFFunction)


def test_get_control_by_id_returns_correct_control():
    """Lookup by ID returns the right control."""
    catalog = CSFControlCatalog()
    control = catalog.get_control("ID.AM-1")
    assert control is not None
    assert control.id == "ID.AM-1"
    assert control.function == CSFFunction.IDENTIFY


def test_get_control_by_id_raises_for_unknown_id():
    """Unknown control ID raises KeyError."""
    catalog = CSFControlCatalog()
    with pytest.raises(KeyError):
        catalog.get_control("XX.XX-99")


def test_get_controls_by_function_filters_correctly():
    """Filtering by function returns only matching controls."""
    catalog = CSFControlCatalog()
    protect_controls = catalog.get_controls_by_function(CSFFunction.PROTECT)
    assert len(protect_controls) > 0
    assert all(c.function == CSFFunction.PROTECT for c in protect_controls)


def test_catalog_controls_have_unique_ids():
    """All control IDs in the catalog are unique."""
    catalog = CSFControlCatalog()
    ids = [c.id for c in catalog.all_controls()]
    assert len(ids) == len(set(ids))


# ── ControlAssessment ──────────────────────────────────────────────────────

def test_assess_control_sets_status():
    """Assessing a control records its status."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    assessment.assess_control("ID.AM-1", ControlStatus.IMPLEMENTED)
    assert assessment.get_assessment("ID.AM-1") == ControlStatus.IMPLEMENTED


def test_assess_control_with_evidence():
    """Evidence list is stored alongside the assessment."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    evidence = ["asset_inventory_v2.csv", "scan_report_2026.pdf"]
    assessment.assess_control("ID.AM-1", ControlStatus.PARTIALLY_IMPLEMENTED, evidence)
    control = catalog.get_control("ID.AM-1")
    assert control.evidence == evidence


def test_get_function_score_returns_zero_when_no_assessments():
    """Function score is 0% when no controls are assessed."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    score = assessment.get_function_score(CSFFunction.IDENTIFY)
    assert score == 0.0


def test_get_function_score_calculates_percentage():
    """Function score is the percentage of max possible status value."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    # Assess all IDENTIFY controls
    id_controls = catalog.get_controls_by_function(CSFFunction.IDENTIFY)
    for c in id_controls:
        assessment.assess_control(c.id, ControlStatus.IMPLEMENTED)
    score = assessment.get_function_score(CSFFunction.IDENTIFY)
    assert score == 100.0


def test_get_function_score_partial_implementation():
    """Partial implementation yields a score between 0 and 100."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    id_controls = catalog.get_controls_by_function(CSFFunction.IDENTIFY)
    # Assess only the first control as partially implemented
    assessment.assess_control(id_controls[0].id, ControlStatus.PARTIALLY_IMPLEMENTED)
    score = assessment.get_function_score(CSFFunction.IDENTIFY)
    assert 0.0 < score < 100.0


def test_get_overall_score_calculates_percentage():
    """Overall score aggregates all assessed controls."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    # Assess all controls as implemented
    for c in catalog.all_controls():
        assessment.assess_control(c.id, ControlStatus.IMPLEMENTED)
    score = assessment.get_overall_score()
    assert score == 100.0


def test_get_overall_score_zero_when_nothing_assessed():
    """Overall score is 0% when no controls are assessed."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    assert assessment.get_overall_score() == 0.0


# ── GapAnalysis ────────────────────────────────────────────────────────────

def test_identify_gaps_returns_unimplemented_controls():
    """Unimplemented controls appear as gaps."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    gap_analysis = GapAnalysis(assessment)
    gaps = gap_analysis.identify_gaps()
    assert len(gaps) > 0
    assert all(g.current_status != ControlStatus.IMPLEMENTED for g in gaps)


def test_identify_gaps_excludes_implemented_controls():
    """Fully implemented controls do not appear as gaps."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    # Implement everything
    for c in catalog.all_controls():
        assessment.assess_control(c.id, ControlStatus.IMPLEMENTED)
    gap_analysis = GapAnalysis(assessment)
    gaps = gap_analysis.identify_gaps()
    assert len(gaps) == 0


def test_get_critical_gaps_filters_by_severity():
    """Critical gaps are filtered correctly."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    gap_analysis = GapAnalysis(assessment)
    critical_gaps = gap_analysis.get_critical_gaps()
    assert all(g.severity == "critical" for g in critical_gaps)


def test_get_gaps_by_function_filters_correctly():
    """Gaps can be filtered by CSF function."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    gap_analysis = GapAnalysis(assessment)
    govern_gaps = gap_analysis.get_gaps_by_function(CSFFunction.GOVERN)
    assert all(g.function == CSFFunction.GOVERN for g in govern_gaps)


def test_gap_severity_is_critical_for_govern_function():
    """GOVERN function gaps are always critical severity."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    gap_analysis = GapAnalysis(assessment)
    govern_gaps = gap_analysis.get_gaps_by_function(CSFFunction.GOVERN)
    assert len(govern_gaps) > 0
    assert all(g.severity == "critical" for g in govern_gaps)


def test_gap_severity_is_high_for_respond_function():
    """RESPOND function gaps are high severity."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    gap_analysis = GapAnalysis(assessment)
    respond_gaps = gap_analysis.get_gaps_by_function(CSFFunction.RESPOND)
    assert len(respond_gaps) > 0
    assert all(g.severity == "high" for g in respond_gaps)


def test_gap_severity_is_medium_for_protect_function():
    """PROTECT function gaps are medium severity."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    gap_analysis = GapAnalysis(assessment)
    protect_gaps = gap_analysis.get_gaps_by_function(CSFFunction.PROTECT)
    assert len(protect_gaps) > 0
    assert all(g.severity == "medium" for g in protect_gaps)


def test_gap_severity_is_low_for_recover_function():
    """RECOVER function gaps are low severity."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    gap_analysis = GapAnalysis(assessment)
    recover_gaps = gap_analysis.get_gaps_by_function(CSFFunction.RECOVER)
    assert len(recover_gaps) > 0
    assert all(g.severity == "low" for g in recover_gaps)


def test_gap_count_matches_unimplemented_controls():
    """Gap count equals the number of non-implemented controls."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    gap_analysis = GapAnalysis(assessment)
    assert gap_analysis.get_gap_count() == len(gap_analysis.identify_gaps())


# ── CISAComplianceReport ───────────────────────────────────────────────────

def test_compliance_report_summary_has_required_fields():
    """Report summary contains all required fields."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    gap_analysis = GapAnalysis(assessment)
    report = CISAComplianceReport(assessment, gap_analysis)
    summary = report.generate_summary()
    assert "overall_score" in summary
    assert "total_controls" in summary
    assert "implemented_controls" in summary
    assert "gap_count" in summary
    assert "function_scores" in summary


def test_compliance_report_function_breakdown():
    """Function breakdown covers all six functions."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    gap_analysis = GapAnalysis(assessment)
    report = CISAComplianceReport(assessment, gap_analysis)
    breakdown = report.generate_function_breakdown()
    assert set(breakdown.keys()) == {f.name for f in CSFFunction}


def test_compliance_report_to_dict_serializes():
    """Report can be serialized to a dictionary."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    gap_analysis = GapAnalysis(assessment)
    report = CISAComplianceReport(assessment, gap_analysis)
    data = report.to_dict()
    assert isinstance(data, dict)
    assert "summary" in data
    assert "function_breakdown" in data
    assert "gaps" in data


# ── Serialization ──────────────────────────────────────────────────────────

def test_control_to_dict_serializes_correctly():
    """Control dataclass serializes to a dict."""
    catalog = CSFControlCatalog()
    control = catalog.get_control("ID.AM-1")
    data = control.to_dict()
    assert data["id"] == "ID.AM-1"
    assert data["name"] == control.name
    assert data["function"] == "IDENTIFY"
    assert data["status"] == "NOT_IMPLEMENTED"


def test_gap_to_dict_serializes_correctly():
    """Gap dataclass serializes to a dict."""
    catalog = CSFControlCatalog()
    assessment = ControlAssessment(catalog)
    gap_analysis = GapAnalysis(assessment)
    gaps = gap_analysis.identify_gaps()
    if gaps:
        data = gaps[0].to_dict()
        assert "control_id" in data
        assert "control_name" in data
        assert "function" in data
        assert "severity" in data
        assert "recommendation" in data
