"""Regex-based risk detection rules for Terms & Privacy Policy analysis.

Each rule consists of a compiled regex pattern, a risk category, a severity
level, a plain-English description of the threat, and a user recommendation.
"""

import re
from dataclasses import dataclass, field
from typing import ClassVar

from app.engine.risk_categories import RiskCategory, SeverityLevel


@dataclass(frozen=True)
class RiskRule:
    """A single risk detection rule."""
    rule_id: str
    category: RiskCategory
    severity: SeverityLevel
    pattern: re.Pattern
    description: str
    recommendation: str


def _compile(pattern_str: str) -> re.Pattern:
    """Compile a regex pattern with IGNORECASE and DOTALL flags."""
    return re.compile(pattern_str, re.IGNORECASE | re.DOTALL)


# ──────────────────────────────────────────────────────────────
# RULE DATABASE
# ──────────────────────────────────────────────────────────────

RISK_RULES: list[RiskRule] = [

    # ── DATA SELLING ──────────────────────────────────────────
    RiskRule(
        rule_id="DATA_SELL_001",
        category=RiskCategory.DATA_SELLING,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:share|sell|disclose|transfer|provide)\s.{0,60}?(?:personal|user)\s.{0,30}?(?:data|information)\s.{0,40}?(?:third.part|advertis|market|partner|vendor|broker)"),
        description="Your personal data may be sold or shared with third-party advertisers or data brokers.",
        recommendation="Avoid this app or opt out of data sharing if possible.",
    ),
    RiskRule(
        rule_id="DATA_SELL_002",
        category=RiskCategory.DATA_SELLING,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:share|provide)\s.{0,40}?(?:aggregated|anonymized|de.identified)\s.{0,30}?(?:data|information)"),
        description="Anonymized or aggregated data may be shared with third parties.",
        recommendation="Lower risk, but check if anonymization is truly irreversible.",
    ),
    RiskRule(
        rule_id="DATA_SELL_003",
        category=RiskCategory.DATA_SELLING,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:monetiz|commercializ)\w*\s.{0,40}?(?:user|personal|your)\s.{0,20}?(?:data|information)"),
        description="The company may monetize or commercialize your personal data.",
        recommendation="This is a major red flag. Avoid providing sensitive data.",
    ),
    RiskRule(
        rule_id="DATA_SELL_004",
        category=RiskCategory.DATA_SELLING,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:data|information).{0,40}?(?:may|will|could)\s.{0,20}?(?:be\s)?(?:shared|disclosed|transferred)"),
        description="Your data may be shared or disclosed to other parties.",
        recommendation="Review who the data is shared with and for what purpose.",
    ),

    # ── CONTACT ACCESS ────────────────────────────────────────
    RiskRule(
        rule_id="CONTACT_001",
        category=RiskCategory.CONTACT_ACCESS,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:access|read|collect|upload|sync)\s.{0,30}?(?:contact\s?list|phone\s?book|address\s?book)"),
        description="This app may access and upload your phone contacts.",
        recommendation="Deny contact permissions. This is a common predatory loan app tactic.",
    ),
    RiskRule(
        rule_id="CONTACT_002",
        category=RiskCategory.CONTACT_ACCESS,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:access|read|collect|monitor)\s.{0,30}?(?:call\s?log|sms|text\s?message|message\s?histor)"),
        description="This app may read your call logs or SMS messages.",
        recommendation="Major privacy violation. Do not grant SMS/call log permissions.",
    ),
    RiskRule(
        rule_id="CONTACT_003",
        category=RiskCategory.CONTACT_ACCESS,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:contact|notify|inform|reach\s?out\s?to)\s.{0,40}?(?:your\s)?(?:contacts|references|friends|family|employer)"),
        description="The app may contact your friends, family, or employer (common in predatory loans).",
        recommendation="Extreme red flag — typical of predatory loan harassment tactics.",
    ),

    # ── FINANCIAL / AUTO-DEBIT ────────────────────────────────
    RiskRule(
        rule_id="FIN_001",
        category=RiskCategory.FINANCIAL_AUTO_DEBIT,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:auto|automatic)\s?.{0,10}?(?:debit|charge|deduct|withdraw|payment)"),
        description="Automatic debits or charges may be applied to your account.",
        recommendation="Ensure you understand the payment schedule and can cancel.",
    ),
    RiskRule(
        rule_id="FIN_002",
        category=RiskCategory.FINANCIAL_AUTO_DEBIT,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:hidden|additional|processing|convenience|service)\s.{0,20}?(?:fee|charge|cost|surcharge)"),
        description="Hidden or additional fees may apply.",
        recommendation="Check the full fee schedule before agreeing.",
    ),
    RiskRule(
        rule_id="FIN_003",
        category=RiskCategory.FINANCIAL_AUTO_DEBIT,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:penalt|late\s?fee|overdue\s?charge|default\s?charge|interest\s?rate\s?(?:of|up\s?to)\s?\d{2,})"),
        description="Penalty fees or excessive interest rates may be imposed.",
        recommendation="Read penalty clauses carefully. Interest rates above 36% APR are predatory.",
    ),
    RiskRule(
        rule_id="FIN_004",
        category=RiskCategory.FINANCIAL_AUTO_DEBIT,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:recurring|subscription|auto.?renew)\s.{0,30}?(?:payment|billing|charge)"),
        description="Recurring or auto-renewing payments may be set up.",
        recommendation="Confirm cancellation process before subscribing.",
    ),

    # ── LOCATION TRACKING ─────────────────────────────────────
    RiskRule(
        rule_id="LOC_001",
        category=RiskCategory.LOCATION_TRACKING,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:collect|gather|access|use|obtain)\s.{0,30}?(?:location|gps|geo.?location|geo.?spatial)\s.{0,20}?(?:data|information)"),
        description="Your location data may be collected.",
        recommendation="Grant location access only while using the app.",
    ),
    RiskRule(
        rule_id="LOC_002",
        category=RiskCategory.LOCATION_TRACKING,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:continuous|background|persistent|real.?time|always.?on)\s.{0,20}?(?:location|gps|tracking)"),
        description="Continuous background location tracking is active.",
        recommendation="This is excessive. Deny background location permission.",
    ),
    RiskRule(
        rule_id="LOC_003",
        category=RiskCategory.LOCATION_TRACKING,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:track|monitor)\s.{0,30}?(?:movement|whereabouts|physical\s?location|place)"),
        description="Your physical movements or whereabouts may be monitored.",
        recommendation="Only allow location access for apps that genuinely need it.",
    ),

    # ── CAMERA & MICROPHONE ───────────────────────────────────
    RiskRule(
        rule_id="CAM_001",
        category=RiskCategory.CAMERA_MIC_ACCESS,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:access|use|activate)\s.{0,20}?(?:camera|photo\s?library|video\s?record)"),
        description="The app may access your camera or photo library.",
        recommendation="Only grant camera access if the app's core function requires it.",
    ),
    RiskRule(
        rule_id="CAM_002",
        category=RiskCategory.CAMERA_MIC_ACCESS,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:access|use|activate|record)\s.{0,20}?(?:microphone|audio|voice)\s.{0,30}?(?:background|without|any\s?time|continuously)"),
        description="The app may record audio in the background without your knowledge.",
        recommendation="Major privacy risk. Deny microphone access.",
    ),
    RiskRule(
        rule_id="CAM_003",
        category=RiskCategory.CAMERA_MIC_ACCESS,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:access|use|activate|record)\s.{0,20}?(?:microphone|audio|voice)"),
        description="The app may access your microphone.",
        recommendation="Grant microphone access only when necessary.",
    ),

    # ── DATA RETENTION ────────────────────────────────────────
    RiskRule(
        rule_id="RETAIN_001",
        category=RiskCategory.DATA_RETENTION,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:retain|store|keep)\s.{0,40}?(?:data|information)\s.{0,30}?(?:indefinite|perpetual|forever|permanent|unlimited\s?(?:time|period))"),
        description="Your data may be stored indefinitely.",
        recommendation="Look for data deletion or account termination options.",
    ),
    RiskRule(
        rule_id="RETAIN_002",
        category=RiskCategory.DATA_RETENTION,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:retain\w*|stor\w*|keep\w*).{0,40}?(?:data|information).{0,30}?(?:after|even\s?(?:if|after|when)).{0,30}?(?:delet|terminat|clos|deactivat)"),
        description="Your data may be retained even after you delete your account.",
        recommendation="Request explicit data deletion under GDPR/DPDPA rights.",
    ),
    RiskRule(
        rule_id="RETAIN_003",
        category=RiskCategory.DATA_RETENTION,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:no|cannot|unable\s?to|not\s?(?:able|possible))\s.{0,20}?(?:delet|remov|eras)\s.{0,20}?(?:data|information|account)"),
        description="There may be no option to delete your data or account.",
        recommendation="This may violate your right to erasure. Consider alternatives.",
    ),

    # ── WAIVER OF RIGHTS ──────────────────────────────────────
    RiskRule(
        rule_id="WAIVER_001",
        category=RiskCategory.WAIVER_OF_RIGHTS,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:waiv\w*|relinquish\w*|surrender\w*|give\s?up|forgo\w*).{0,30}?(?:right|claim|entitlement).{0,30}?(?:class.?action|lawsuit|legal\s?action|litigation)"),
        description="You may be waiving your right to file a lawsuit or class-action.",
        recommendation="This limits your legal recourse. Consult legal advice if concerned.",
    ),
    RiskRule(
        rule_id="WAIVER_002",
        category=RiskCategory.WAIVER_OF_RIGHTS,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:binding|mandatory|compulsory|forced)\s.{0,15}?(?:arbitration)"),
        description="Disputes must be resolved through binding arbitration (no court).",
        recommendation="You lose your right to a jury trial. Understand the implications.",
    ),
    RiskRule(
        rule_id="WAIVER_003",
        category=RiskCategory.WAIVER_OF_RIGHTS,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:limit|cap|restrict|exclud)\s.{0,30}?(?:liability|damage|compensation|responsib)"),
        description="The company limits its liability for damages.",
        recommendation="Standard but worth noting — check the extent of limitation.",
    ),

    # ── UNILATERAL CHANGES ────────────────────────────────────
    RiskRule(
        rule_id="CHANGE_001",
        category=RiskCategory.UNILATERAL_CHANGES,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:modif\w*|chang\w*|updat\w*|revis\w*|amend\w*).{0,30}?(?:term|polic|agreement|condition).{0,30}?(?:at\s?any\s?time|without\s?(?:prior\s?)?notice|without\s?(?:your\s?)?consent|sole\s?discretion)"),
        description="Terms may be changed at any time without notifying you.",
        recommendation="Bookmark and periodically review the terms page.",
    ),
    RiskRule(
        rule_id="CHANGE_002",
        category=RiskCategory.UNILATERAL_CHANGES,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:continued|ongoing|further).{0,20}?(?:use|access|usage).{0,30}?(?:constitut\w*|signif\w*|indicat\w*|mean\w*|impl\w*).{0,20}?(?:accept|agree|consent)"),
        description="Continuing to use the service means you accept any changes automatically.",
        recommendation="Be aware that silence = consent for policy changes.",
    ),

    # ── ACCOUNT TERMINATION ───────────────────────────────────
    RiskRule(
        rule_id="TERM_001",
        category=RiskCategory.ACCOUNT_TERMINATION,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:terminat\w*|suspend\w*|deactivat\w*|delet\w*|ban\w*).{0,30}?(?:account|access|service).{0,40}?(?:at\s?any\s?time|without\s?(?:prior\s?)?(?:notice|reason|cause)|sole\s?discretion)"),
        description="Your account may be terminated without notice or reason.",
        recommendation="Export your data regularly in case of sudden termination.",
    ),
    RiskRule(
        rule_id="TERM_002",
        category=RiskCategory.ACCOUNT_TERMINATION,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:terminat\w*|suspend\w*|cancel\w*).{0,30}?(?:account|service).{0,40}?(?:without|no).{0,15}?(?:refund|reimburs\w*|compensation)"),
        description="Account termination may occur without any refund.",
        recommendation="Be cautious about prepaying or long-term commitments.",
    ),

    # ── CHILD DATA ────────────────────────────────────────────
    RiskRule(
        rule_id="CHILD_001",
        category=RiskCategory.CHILD_DATA,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?<!not\s)(?<!knowingly\s)(?:collect\w*|gather\w*|process\w*).{0,40}?(?:data|information).{0,30}?(?:from|of).{0,20}?(?:child\w*|minor\w*|under\s?(?:13|16|18)|kid\w*|teen\w*)"),
        description="Data may be collected from children or minors.",
        recommendation="Verify COPPA/age-gate compliance. Report if targeting minors.",
    ),
    RiskRule(
        rule_id="CHILD_002",
        category=RiskCategory.CHILD_DATA,
        severity=SeverityLevel.GREEN,
        pattern=_compile(r"(?:do\s?not|does\s?not|never)\s.{0,20}?(?:knowingly)\s.{0,20}?(?:collect|gather)\s.{0,30}?(?:child|minor|under\s?(?:13|16|18))"),
        description="The service states it does not knowingly collect data from children.",
        recommendation="Good sign — standard COPPA compliance language.",
    ),

    # ── BIOMETRIC DATA ────────────────────────────────────────
    RiskRule(
        rule_id="BIO_001",
        category=RiskCategory.BIOMETRIC_DATA,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:collect|capture|store|process|scan)\s.{0,30}?(?:biometric|fingerprint|face\s?(?:scan|recogni|print|id)|iris|retina|voice\s?print|palm\s?print)"),
        description="Biometric data (fingerprints, face scans, etc.) may be collected.",
        recommendation="Biometric data is permanent — once leaked, it cannot be changed.",
    ),
    RiskRule(
        rule_id="BIO_002",
        category=RiskCategory.BIOMETRIC_DATA,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:facial|face)\s.{0,15}?(?:recogni|detect|analy)"),
        description="Facial recognition or analysis technology may be used.",
        recommendation="Understand how and where your facial data is processed.",
    ),

    # ── CROSS-DEVICE TRACKING ─────────────────────────────────
    RiskRule(
        rule_id="CROSS_001",
        category=RiskCategory.CROSS_DEVICE_TRACKING,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:track|monitor|follow|identif)\s.{0,30}?(?:across|between|multiple)\s.{0,20}?(?:device|platform|service|browser|app)"),
        description="You may be tracked across multiple devices or platforms.",
        recommendation="Use privacy-focused browsers and limit cross-app tracking.",
    ),
    RiskRule(
        rule_id="CROSS_002",
        category=RiskCategory.CROSS_DEVICE_TRACKING,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:device\s?fingerprint|browser\s?fingerprint|canvas\s?fingerprint|unique\s?(?:device\s?)?identifier)"),
        description="Device or browser fingerprinting may be used to identify you.",
        recommendation="Consider using fingerprint-resistant browser extensions.",
    ),
    RiskRule(
        rule_id="CROSS_003",
        category=RiskCategory.CROSS_DEVICE_TRACKING,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:advertising\s?id|ad\s?identifier|idfa|gaid|tracking\s?cookie|pixel\s?tag|web\s?beacon)"),
        description="Advertising identifiers or tracking technologies are used.",
        recommendation="Reset your advertising ID regularly and opt out where possible.",
    ),

    # ── ADDITIONAL RULES ─────────────────────────────────────────
    RiskRule(
        rule_id="DATA_SELL_005",
        category=RiskCategory.DATA_SELLING,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:without|no)\s.{0,20}?(?:explicit|prior)?\s?(?:consent|permission|authorization).{0,40}?(?:share|sell|transfer|disclose)\s.{0,30}?(?:data|information)"),
        description="Your data may be shared without your explicit consent.",
        recommendation="Look for opt-in consent mechanisms before sharing any data.",
    ),
    RiskRule(
        rule_id="CONTACT_004",
        category=RiskCategory.CONTACT_ACCESS,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:access|read|scan|collect)\s.{0,30}?(?:storage|gallery|photo|file|media)\s.{0,20}?(?:on\s?your|device|phone)"),
        description="The app may access your device storage, photos, or files.",
        recommendation="Only grant storage access if the app genuinely needs it.",
    ),
    RiskRule(
        rule_id="FIN_005",
        category=RiskCategory.FINANCIAL_AUTO_DEBIT,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:interest\s?rate|apr|annual\s?percentage)\s.{0,20}?(?:exceed|above|over|up\s?to)\s.{0,10}?\d{2,3}\s?%"),
        description="Interest rates may exceed standard limits (potentially predatory lending).",
        recommendation="Compare rates with regulated lenders. Rates above 36% APR are predatory.",
    ),
    RiskRule(
        rule_id="LOC_004",
        category=RiskCategory.LOCATION_TRACKING,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:install|app)\s.{0,30}?(?:track|monitor|record)\s.{0,20}?(?:location|position|gps).{0,30}?(?:even\s?(?:when|if|after)|without)"),
        description="The app may track your location even when not in use.",
        recommendation="Revoke location permissions in your phone settings.",
    ),
    RiskRule(
        rule_id="DATA_SELL_006",
        category=RiskCategory.DATA_SELLING,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:share|provide|disclose)\s.{0,40}?(?:data|information)\s.{0,30}?(?:government|law\s?enforcement|authorit|regulator|court\s?order)"),
        description="Your data may be shared with government or law enforcement.",
        recommendation="Standard for legal compliance, but verify scope of disclosure.",
    ),
    RiskRule(
        rule_id="CAM_004",
        category=RiskCategory.CAMERA_MIC_ACCESS,
        severity=SeverityLevel.RED,
        pattern=_compile(r"(?:screen\s?record|screen\s?capture|screenshot|record\s?your\s?screen)"),
        description="The app may record or capture your screen.",
        recommendation="Screen recording can expose sensitive info. Deny unless essential.",
    ),
    RiskRule(
        rule_id="CROSS_004",
        category=RiskCategory.CROSS_DEVICE_TRACKING,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:social\s?media|facebook|instagram|twitter|linkedin)\s.{0,30}?(?:profile|data|information|activity|interaction)"),
        description="Your social media activity or profile data may be collected.",
        recommendation="Review app connections in your social media privacy settings.",
    ),
    RiskRule(
        rule_id="CROSS_005",
        category=RiskCategory.CROSS_DEVICE_TRACKING,
        severity=SeverityLevel.YELLOW,
        pattern=_compile(r"(?:wi.?fi|bluetooth|nearby\s?device|beacon)\s.{0,30}?(?:scan|detect|track|monitor|collect)"),
        description="WiFi, Bluetooth, or nearby device scanning may be used for tracking.",
        recommendation="Disable WiFi/Bluetooth scanning in your phone's location settings.",
    ),
]


def get_rules_by_category(category: RiskCategory) -> list[RiskRule]:
    """Return all rules belonging to a specific risk category."""
    return [r for r in RISK_RULES if r.category == category]


def get_rules_by_severity(severity: SeverityLevel) -> list[RiskRule]:
    """Return all rules matching a specific severity level."""
    return [r for r in RISK_RULES if r.severity == severity]


def get_rule_by_id(rule_id: str) -> RiskRule | None:
    """Look up a single rule by its ID."""
    for rule in RISK_RULES:
        if rule.rule_id == rule_id:
            return rule
    return None
