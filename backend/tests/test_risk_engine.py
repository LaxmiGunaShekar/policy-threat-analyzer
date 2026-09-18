"""Integration tests for the RiskAnalyzer engine."""

import os
import pytest
from app.engine.risk_engine import RiskAnalyzer
from app.models.schemas import RiskReport


SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "sample_policies")


@pytest.fixture
def analyzer():
    """Create a fresh RiskAnalyzer instance."""
    return RiskAnalyzer()


@pytest.fixture
def predatory_policy():
    """Load the predatory loan app policy text."""
    path = os.path.join(SAMPLE_DIR, "predatory_loan_app.txt")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def benign_policy():
    """Load the benign app policy text."""
    path = os.path.join(SAMPLE_DIR, "benign_app.txt")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class TestRiskAnalyzerBasic:
    """Basic engine tests."""

    def test_empty_text(self, analyzer):
        report = analyzer.analyze("")
        assert report.total_matches == 0
        assert report.overall_risk_score == 0
        assert report.risk_level == "safe"

    def test_whitespace_only(self, analyzer):
        report = analyzer.analyze("   \n\t   ")
        assert report.total_matches == 0
        assert report.overall_risk_score == 0

    def test_clean_text(self, analyzer):
        report = analyzer.analyze("This is a simple sentence with no policy language.")
        assert report.total_matches == 0
        assert report.overall_risk_score == 0
        assert report.risk_level == "safe"

    def test_report_structure(self, analyzer):
        report = analyzer.analyze("We may share your personal data with third-party advertisers.")
        assert isinstance(report, RiskReport)
        assert hasattr(report, 'total_matches')
        assert hasattr(report, 'overall_risk_score')
        assert hasattr(report, 'risk_level')
        assert hasattr(report, 'severity_counts')
        assert hasattr(report, 'matches')
        assert hasattr(report, 'summary')


class TestPredatoryPolicy:
    """Tests against the predatory loan app policy."""

    def test_predatory_score_is_dangerous(self, analyzer, predatory_policy):
        report = analyzer.analyze(predatory_policy)
        assert report.overall_risk_score > 50, (
            f"Predatory policy should score > 50 (dangerous), got {report.overall_risk_score}"
        )

    def test_predatory_level_is_dangerous(self, analyzer, predatory_policy):
        report = analyzer.analyze(predatory_policy)
        assert report.risk_level == "dangerous"

    def test_predatory_has_red_flags(self, analyzer, predatory_policy):
        report = analyzer.analyze(predatory_policy)
        assert report.severity_counts.red >= 5, (
            f"Expected at least 5 RED flags in predatory policy, got {report.severity_counts.red}"
        )

    def test_predatory_detects_contact_access(self, analyzer, predatory_policy):
        report = analyzer.analyze(predatory_policy)
        categories = {m.category for m in report.matches}
        assert "Contact List Access" in categories

    def test_predatory_detects_data_selling(self, analyzer, predatory_policy):
        report = analyzer.analyze(predatory_policy)
        categories = {m.category for m in report.matches}
        assert "Data Selling to Third Parties" in categories

    def test_predatory_detects_auto_debit(self, analyzer, predatory_policy):
        report = analyzer.analyze(predatory_policy)
        categories = {m.category for m in report.matches}
        assert "Auto-Debit & Financial Penalties" in categories

    def test_predatory_has_summary(self, analyzer, predatory_policy):
        report = analyzer.analyze(predatory_policy)
        assert len(report.summary) > 50
        assert "critical" in report.summary.lower() or "red" in report.summary.lower() or "CRITICAL" in report.summary


class TestBenignPolicy:
    """Tests against the benign app policy."""

    def test_benign_score_is_safe(self, analyzer, benign_policy):
        report = analyzer.analyze(benign_policy)
        assert report.overall_risk_score < 25, (
            f"Benign policy should score < 25 (safe), got {report.overall_risk_score}"
        )

    def test_benign_has_no_red_flags(self, analyzer, benign_policy):
        report = analyzer.analyze(benign_policy)
        assert report.severity_counts.red == 0, (
            f"Benign policy should have 0 RED flags, got {report.severity_counts.red}. "
            f"Red matches: {[(m.rule_id, m.matched_text) for m in report.matches if m.severity == 'red']}"
        )

    def test_benign_level_is_safe(self, analyzer, benign_policy):
        report = analyzer.analyze(benign_policy)
        assert report.risk_level == "safe"


class TestScoring:
    """Tests for score calculation logic."""

    def test_score_capped_at_100(self, analyzer):
        """Even with many matches, score should not exceed 100."""
        # Create text that triggers many rules
        heavy_text = " ".join([
            "We share your personal data with third-party advertisers.",
            "We access your contact list and phone book.",
            "We read your call log and SMS messages.",
            "We may contact your friends and family.",
            "Automatic debit from your bank account.",
            "Additional processing fees apply.",
            "Late fees of up to 50% will be charged.",
            "Continuous location tracking in background.",
            "We record your microphone audio in background.",
            "We retain your data indefinitely.",
            "You waive your right to class-action lawsuit.",
            "Mandatory binding arbitration only.",
            "We collect biometric fingerprint data.",
        ])
        report = analyzer.analyze(heavy_text)
        assert report.overall_risk_score <= 100

    def test_single_red_scores_10(self, analyzer):
        text = "You authorize automatic debit from your bank account."
        report = analyzer.analyze(text)
        red_matches = [m for m in report.matches if m.severity == "red"]
        if len(red_matches) == 1:
            assert report.overall_risk_score == 10

    def test_risk_level_safe_threshold(self, analyzer):
        """Score 0-20 should be 'safe'."""
        report = analyzer.analyze("We protect your data with encryption.")
        assert report.risk_level == "safe"
