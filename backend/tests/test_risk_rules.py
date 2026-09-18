"""Unit tests for individual risk detection rules."""

import pytest
from app.engine.risk_rules import RISK_RULES, get_rule_by_id, get_rules_by_category, get_rules_by_severity
from app.engine.risk_categories import RiskCategory, SeverityLevel


class TestRuleDatabase:
    """Tests for the rule database integrity."""

    def test_minimum_rule_count(self):
        """Ensure we have at least 40 rules defined."""
        assert len(RISK_RULES) >= 40, f"Expected at least 40 rules, got {len(RISK_RULES)}"

    def test_no_duplicate_rule_ids(self):
        """All rule IDs must be unique."""
        ids = [r.rule_id for r in RISK_RULES]
        duplicates = [rid for rid in ids if ids.count(rid) > 1]
        assert len(duplicates) == 0, f"Duplicate rule IDs found: {set(duplicates)}"

    def test_all_categories_covered(self):
        """Every RiskCategory must have at least one rule."""
        covered = {r.category for r in RISK_RULES}
        for cat in RiskCategory:
            assert cat in covered, f"No rules defined for category: {cat.name}"

    def test_all_rules_have_descriptions(self):
        """Every rule must have a non-empty description and recommendation."""
        for rule in RISK_RULES:
            assert rule.description.strip(), f"{rule.rule_id} has empty description"
            assert rule.recommendation.strip(), f"{rule.rule_id} has empty recommendation"

    def test_all_patterns_compile(self):
        """All regex patterns must be valid (already compiled at import time)."""
        for rule in RISK_RULES:
            # If pattern didn't compile, this would have failed at import
            assert rule.pattern is not None, f"{rule.rule_id} has None pattern"


class TestRuleLookup:
    """Tests for rule lookup functions."""

    def test_get_rule_by_id_existing(self):
        rule = get_rule_by_id("DATA_SELL_001")
        assert rule is not None
        assert rule.category == RiskCategory.DATA_SELLING

    def test_get_rule_by_id_nonexistent(self):
        rule = get_rule_by_id("FAKE_RULE_999")
        assert rule is None

    def test_get_rules_by_category(self):
        rules = get_rules_by_category(RiskCategory.DATA_SELLING)
        assert len(rules) >= 2
        assert all(r.category == RiskCategory.DATA_SELLING for r in rules)

    def test_get_rules_by_severity(self):
        red_rules = get_rules_by_severity(SeverityLevel.RED)
        assert len(red_rules) >= 10, "Expected at least 10 RED rules"
        assert all(r.severity == SeverityLevel.RED for r in red_rules)


class TestIndividualRuleMatching:
    """Test specific rules against known positive and negative text snippets."""

    @pytest.mark.parametrize("rule_id,text,should_match", [
        # DATA SELLING
        ("DATA_SELL_001", "We may share your personal data with third-party advertisers", True),
        ("DATA_SELL_001", "We protect your data with encryption", False),
        ("DATA_SELL_002", "We share aggregated data with research partners", True),
        ("DATA_SELL_002", "We share your personal data with partners", False),
        ("DATA_SELL_003", "We may monetize user data for business purposes", True),
        # CONTACT ACCESS
        ("CONTACT_001", "We access your contact list to verify identity", True),
        ("CONTACT_001", "Contact us at support@example.com", False),
        ("CONTACT_002", "We may access and read your call log and SMS messages", True),
        ("CONTACT_003", "We may contact your friends and family regarding dues", True),
        # FINANCIAL
        ("FIN_001", "You authorize automatic debit from your account", True),
        ("FIN_001", "Please pay your monthly bill on time", False),
        ("FIN_002", "Additional processing fees may apply", True),
        ("FIN_003", "Late fees of up to 36% will be charged", True),
        ("FIN_004", "Auto-renewing subscription payment will be charged", True),
        # LOCATION
        ("LOC_001", "We collect your location data for navigation", True),
        ("LOC_002", "We use continuous location tracking in the background", True),
        ("LOC_002", "We collect your location when you open the app", False),
        # CAMERA/MIC
        ("CAM_001", "We may access your camera for photo uploads", True),
        ("CAM_003", "We may access your microphone for voice commands", True),
        # DATA RETENTION
        ("RETAIN_001", "We retain your data and information indefinitely", True),
        ("RETAIN_001", "We retain data for 30 days", False),
        ("RETAIN_002", "We retain data even after you delete your account", True),
        # WAIVER
        ("WAIVER_001", "You waive your right to class-action litigation", True),
        ("WAIVER_002", "Disputes are resolved through mandatory binding arbitration", True),
        ("WAIVER_003", "We limit our liability for damages", True),
        # UNILATERAL CHANGES
        ("CHANGE_001", "We may modify these terms at any time without notice", True),
        ("CHANGE_002", "Continued use of the service constitutes acceptance of changes", True),
        # ACCOUNT TERMINATION
        ("TERM_001", "We may terminate your account at any time without notice", True),
        ("TERM_002", "Upon termination of your account, no refund will be provided", True),
        # CHILD DATA
        ("CHILD_002", "We do not knowingly collect data from children under 13", True),
        # BIOMETRIC
        ("BIO_001", "We collect biometric data including fingerprint and face scan", True),
        ("BIO_002", "We use facial recognition technology", True),
        # CROSS-DEVICE
        ("CROSS_001", "We track your activity across multiple devices and platforms", True),
        ("CROSS_002", "We use device fingerprinting to identify users", True),
        ("CROSS_003", "We use advertising ID and tracking cookies", True),
    ])
    def test_rule_matching(self, rule_id: str, text: str, should_match: bool):
        """Test that a specific rule matches (or doesn't match) a text snippet."""
        rule = get_rule_by_id(rule_id)
        assert rule is not None, f"Rule {rule_id} not found"
        match = rule.pattern.search(text)
        if should_match:
            assert match is not None, (
                f"Rule {rule_id} should match: '{text}'"
            )
        else:
            assert match is None, (
                f"Rule {rule_id} should NOT match: '{text}' "
                f"but matched: '{match.group(0) if match else ''}'"
            )
