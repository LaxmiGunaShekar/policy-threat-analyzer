"""Core risk analysis engine.

Scans policy text against all defined risk rules, extracts matching clauses
with surrounding context, and produces a structured risk report with scores.
"""

from app.engine.risk_categories import SeverityLevel
from app.engine.risk_rules import RISK_RULES, RiskRule
from app.models.schemas import RiskMatch, RiskReport, SeverityCounts


class RiskAnalyzer:
    """Analyzes terms/privacy policy text for predatory or risky clauses."""

    CONTEXT_WINDOW = 250  # characters of surrounding context to extract

    def __init__(self, rules: list[RiskRule] | None = None):
        """Initialize with a set of rules. Defaults to the full rule database."""
        self.rules = rules if rules is not None else RISK_RULES

    def analyze(self, text: str) -> RiskReport:
        """Run all risk rules against the input text and produce a risk report."""
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
        summary = self._generate_summary(matches, score, risk_level, text)

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
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def _find_matches(self, processed_text: str, original_text: str) -> list[RiskMatch]:
        """Run all rules against processed text and collect matches."""
        matches: list[RiskMatch] = []
        seen_spans: set[tuple[str, int, int]] = set()

        for rule in self.rules:
            for match in rule.pattern.finditer(processed_text):
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

        severity_order = {"red": 0, "yellow": 1, "green": 2}
        matches.sort(key=lambda m: severity_order.get(m.severity, 99))
        return matches

    def _extract_context(
        self, text: str, match_start: int, match_end: int
    ) -> str:
        ctx_start = max(0, match_start - self.CONTEXT_WINDOW)
        ctx_end = min(len(text), match_end + self.CONTEXT_WINDOW)

        if ctx_start > 0:
            space_pos = text.find(' ', ctx_start)
            if space_pos != -1 and space_pos < match_start:
                ctx_start = space_pos + 1

        if ctx_end < len(text):
            space_pos = text.rfind(' ', match_end, ctx_end)
            if space_pos != -1:
                ctx_end = space_pos

        snippet = text[ctx_start:ctx_end].strip()

        if ctx_start > 0:
            snippet = "..." + snippet
        if ctx_end < len(text):
            snippet = snippet + "..."

        return snippet

    def _count_severities(self, matches: list[RiskMatch]) -> SeverityCounts:
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
        """Calculate weighted risk score (0-100) based on UNIQUE categories to avoid repetition bloat."""
        # Get the highest severity for each category
        category_severities = {}
        for m in matches:
            current_weight = category_severities.get(m.category, 0)
            if m.severity == "red":
                category_severities[m.category] = max(current_weight, 20)  # Red category = 20 points
            elif m.severity == "yellow":
                category_severities[m.category] = max(current_weight, 10)  # Yellow category = 10 points
            elif m.severity == "green":
                category_severities[m.category] = max(current_weight, 2)   # Green category = 2 points
                
        total = sum(category_severities.values())
        return min(100, total)

    def _score_to_level(self, score: int) -> str:
        if score <= 25:
            return "safe"
        elif score <= 55:
            return "caution"
        else:
            return "dangerous"

    def _generate_summary(self, matches: list[RiskMatch], score: int, level: str, full_text: str = "") -> str:
        unique_reds = len(set(m.category for m in matches if m.severity == "red"))
        unique_yellows = len(set(m.category for m in matches if m.severity == "yellow"))
        red_categories = list({m.category for m in matches if m.severity == "red"})

        # Standard rule-based fallback summary
        parts = []
        if unique_reds == 0 and unique_yellows == 0:
            parts.append("This policy is relatively standard and doesn't contain any major red flags.")
        else:
            parts.append(f"We found issues in {unique_reds + unique_yellows} different areas.")

        if red_categories:
            parts.append(f"Major concerns include: {', '.join(red_categories)}.")

        if unique_reds >= 3:
            parts.append("⚠️ MULTIPLE CRITICAL RED FLAGS DETECTED. Exercise extreme caution.")
        elif unique_reds >= 1:
            parts.append("⚠️ Review the red flagged clauses below before agreeing.")

        fallback_summary = " ".join(parts)

        # Attempt to use Gemini AI for a smart summary if the API key is configured
        import os
        from dotenv import load_dotenv
        load_dotenv()
        
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return fallback_summary

        try:
            import time
            from google import genai
            client = genai.Client(api_key=api_key)
            
            # Truncate to avoid massive payloads; 30k chars is plenty for the AI
            policy_excerpt = full_text[:30000] if full_text else "No text provided."

            prompt = f"""You are an expert privacy lawyer and consumer advocate. I am providing you with the text of a privacy policy/terms of service.

Please read the policy and write a 3-4 sentence "TL;DR" summary for a non-technical user. 
Focus ONLY on the most predatory, dangerous, or unusual clauses (e.g., selling data, tracking location, accessing contacts, auto-debits, waiving rights).
If the policy is completely standard and safe, reassure the user.

Explain exactly what they are agreeing to in plain, conversational English. Do not use markdown formatting.

POLICY TEXT:
{policy_excerpt}"""

            # Retry up to 3 times with increasing delay for 503 overload errors
            MODEL = 'gemini-3.6-flash'
            last_error = None
            for attempt in range(3):
                try:
                    response = client.models.generate_content(
                        model=MODEL,
                        contents=prompt,
                    )
                    if response and response.text:
                        return f"🤖 AI Analysis: {response.text.strip()}"
                    return fallback_summary
                except Exception as attempt_err:
                    last_error = str(attempt_err)
                    if '503' in last_error or 'UNAVAILABLE' in last_error:
                        wait = (attempt + 1) * 2  # 2s, 4s, 6s
                        print(f"Gemini overloaded, retrying in {wait}s (attempt {attempt + 1}/3)...")
                        time.sleep(wait)
                        continue
                    # Non-retriable error (404, auth, etc.)
                    raise attempt_err

            print(f"Gemini API summarization failed after retries: {last_error}")
            return fallback_summary
        except Exception as e:
            print(f"Gemini API summarization failed: {e}")
            return fallback_summary
