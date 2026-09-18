"""Risk category and severity level definitions for the Terms & Privacy Policy Threat Analyzer."""

from enum import Enum


class SeverityLevel(Enum):
    """Severity levels for flagged clauses."""
    RED = ("red", "Critical", 10)      # Immediate threat
    YELLOW = ("yellow", "Warning", 5)   # Potentially harmful  
    GREEN = ("green", "Info", 1)        # Standard practice, low concern

    def __init__(self, color: str, label: str, weight: int):
        self.color = color
        self.label = label
        self.weight = weight


class RiskCategory(Enum):
    """Categories of privacy and terms risks."""
    DATA_SELLING = ("Data Selling to Third Parties", "Sharing or selling personal data to advertisers, data brokers, or unrelated third parties.")
    CONTACT_ACCESS = ("Contact List Access", "Accessing phone contacts, call logs, or SMS messages.")
    FINANCIAL_AUTO_DEBIT = ("Auto-Debit & Financial Penalties", "Automatic charges, hidden fees, or penalty clauses.")
    LOCATION_TRACKING = ("Location Tracking", "Persistent or background GPS/location monitoring.")
    CAMERA_MIC_ACCESS = ("Camera & Microphone Access", "Accessing device camera or microphone beyond core functionality.")
    DATA_RETENTION = ("Indefinite Data Retention", "Storing user data indefinitely or without a clear deletion mechanism.")
    WAIVER_OF_RIGHTS = ("Waiver of Legal Rights", "Forcing arbitration, waiving class-action rights, or limiting liability.")
    UNILATERAL_CHANGES = ("Unilateral Policy Changes", "Modifying terms without user consent or prior notice.")
    ACCOUNT_TERMINATION = ("Arbitrary Account Termination", "Terminating accounts without cause, notice, or refund.")
    CHILD_DATA = ("Children's Data Collection", "Collecting data from minors without proper safeguards or parental consent.")
    BIOMETRIC_DATA = ("Biometric Data Collection", "Collecting fingerprints, face scans, voice prints, or other biometric identifiers.")
    CROSS_DEVICE_TRACKING = ("Cross-Device Tracking", "Tracking users across multiple devices, platforms, or services.")

    def __init__(self, display_name: str, description: str):
        self.display_name = display_name
        self._description = description

    @property
    def category_description(self) -> str:
        return self._description
