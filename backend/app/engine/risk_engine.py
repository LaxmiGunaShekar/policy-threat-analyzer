"""Core risk analysis engine.

Scans policy text against all defined risk rules, extracts matching clauses
with surrounding context, and produces a structured risk report with scores.
"""

from app.engine.risk_categories import SeverityLevel
from app.engine.risk_rules import RISK_RULES, RiskRule
from app.models.schemas import RiskMatch, RiskReport, SeverityCounts


class RiskAnalyzer:
    """Analyzes terms/privacy policy text for predatory or risky clauses."""

    CONTEXT_WINDOW = 100  # characters of surrounding context to extract

    def __init__(self, rules: list[RiskRule] | None = None):
        """Initialize with a set of rules. Defaults to the full rule database."""
        self.rules = rules if rules is not None else RISK_RULES

    def analyze(self, text: str) -> RiskReport:
        """Run all risk rules against the input text and produce a risk report.

        Args:
            text: The raw policy/terms text to analyze.

        Returns:
            A RiskReport with all matches, scores, and a summary.
        """
        if not text or not text.strip():
            return RiskReport(
                total_matches=0,
                overall_risk_score=0,
                risk_level="safe",
                severity_counts=SeverityCounts(),
                matches=[],
                summary="No text provided for analysis.",
            )

        processed_text = self._preprocess(text)
        matches = self._find_matches(processed_text, text)
        severity_counts = self._count_severities(matches)
        score = self._calculate_score(matches)
        risk_level = self._score_to_level(score)
        summary = self._generate_summary(matches, score, risk_level)

        return RiskReport(
            total_matches=len(matches),
            overall_risk_score=score,
            risk_level=risk_level,
            severity_counts=severity_counts,
            matches=matches,
            summary=summary,
        )

    def _preprocess(self, text: str) -> str:
        """Normalize text for matching: collapse whitespace, strip edges."""
        import re
        # Collapse multiple whitespace (including newlines) into single space
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def _find_matches(self, processed_text: str, original_text: str) -> list[RiskMatch]:
        """Run all rules against processed text and collect matches."""
        matches: list[RiskMatch] = []
        seen_spans: set[tuple[str, int, int]] = set()  # avoid duplicate matches

        for rule in self.rules:
            for match in rule.pattern.finditer(processed_text):
                # Deduplicate: same rule + overlapping span
                span_key = (rule.rule_id, match.start(), match.end())
                if span_key in seen_spans:
                    continue
                seen_spans.add(span_key)

                matched_text = match.group(0).strip()
                context = self._extract_context(
                    processed_text, match.start(), match.end()
                )

                matches.append(RiskMatch(
                    rule_id=rule.rule_id,
                    category=rule.category.display_name,
                    severity=rule.severity.color,
                    severity_label=rule.severity.label,
                    matched_text=matched_text,
                    context_snippet=context,
                    description=rule.description,
                    recommendation=rule.recommendation,
                ))

        # Sort by severity: RED first, then YELLOW, then GREEN
        severity_order = {"red": 0, "yellow": 1, "green": 2}
        matches.sort(key=lambda m: severity_order.get(m.severity, 99))
        return matches

    def _extract_context(
        self, text: str, match_start: int, match_end: int
    ) -> str:
        """Extract surrounding context around a match.

        Returns up to CONTEXT_WINDOW characters before and after the match,
        trimmed to word boundaries.
        """
        ctx_start = max(0, match_start - self.CONTEXT_WINDOW)
        ctx_end = min(len(text), match_end + self.CONTEXT_WINDOW)

        # Trim to word boundaries
        if ctx_start > 0:
            space_pos = text.find(' ', ctx_start)
            if space_pos != -1 and space_pos < match_start:
                ctx_start = space_pos + 1

        if ctx_end < len(text):
            space_pos = text.rfind(' ', match_end, ctx_end)
            if space_pos != -1:
                ctx_end = space_pos

        snippet = text[ctx_start:ctx_end].strip()

        # Add ellipsis indicators
        if ctx_start > 0:
            snippet = "..." + snippet
        if ctx_end < len(text):
            snippet = snippet + "..."

        return snippet

    def _count_severities(self, matches: list[RiskMatch]) -> SeverityCounts:
        """Count matches by severity level."""
        counts = SeverityCounts()
        for m in matches:
            if m.severity == "red":
                counts.red += 1
            elif m.severity == "yellow":
                counts.yellow += 1
            elif m.severity == "green":
                counts.green += 1
        return counts

    def _calculate_score(self, matches: list[RiskMatch]) -> int:
        """Calculate weighted risk score (0-100).

        Weights:
            RED    = 10 points each
            YELLOW = 5 points each
            GREEN  = 1 point each
        """
        weight_map = {
            "red": SeverityLevel.RED.weight,
            "yellow": SeverityLevel.YELLOW.weight,
            "green": SeverityLevel.GREEN.weight,
        }
        total = sum(weight_map.get(m.severity, 0) for m in matches)
        return min(100, total)

    def _score_to_level(self, score: int) -> str:
        """Convert numeric score to risk level label."""
        if score <= 20:
            return "safe"
        elif score <= 50:
            return "caution"
        else:
            return "dangerous"

    def _generate_summary(self, matches: list[RiskMatch], score: int, level: str) -> str:
        """Generate a plain-English summary of findings."""
        if not matches:
            return "No significant risks were detected in this policy."

        red_count = sum(1 for m in matches if m.severity == "red")
        yellow_count = sum(1 for m in matches if m.severity == "yellow")
        green_count = sum(1 for m in matches if m.severity == "green")

        # Collect unique categories with RED flags
        red_categories = list({m.category for m in matches if m.severity == "red"})

        parts = []
        parts.append(f"Risk Score: {score}/100 ({level.upper()}).")
        parts.append(f"Found {len(matches)} concerning clause(s): "
                     f"{red_count} critical, {yellow_count} warnings, {green_count} informational.")

        if red_categories:
            parts.append(f"Critical issues in: {', '.join(red_categories)}.")

        if red_count >= 3:
            parts.append("⚠️ MULTIPLE CRITICAL RED FLAGS DETECTED. "
                         "Exercise extreme caution before agreeing to these terms.")
        elif red_count >= 1:
            parts.append("⚠️ Critical risks found. Review flagged clauses carefully.")

        return " ".join(parts)
