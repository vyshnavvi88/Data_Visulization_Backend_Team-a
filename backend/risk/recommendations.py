"""
recommendations.py
------------------
Task 9 - Response Recommendations Engine

Maps event_type and threat context to actionable
recommendations for security analysts.
"""

# ============================================================
# RECOMMENDATION RULES — keyed by event_type
# ============================================================

RECOMMENDATIONS = {
    "Brute Force": [
        "Temporarily lock the affected user account",
        "Investigate and block the source IP address",
        "Enable Multi-Factor Authentication (MFA) on the account",
        "Review authentication logs for the past 24 hours",
        "Check if account credentials have been compromised (HaveIBeenPwned)",
        "Alert the account owner and reset credentials"
    ],
    "Failed Login": [
        "Monitor the account for further failed attempts",
        "Investigate the source IP for suspicious activity",
        "Consider implementing account lockout policy",
        "Review login history for the affected user",
        "Verify if the user was attempting legitimate access"
    ],
    "Phishing Email": [
        "Quarantine and delete the phishing email from all mailboxes",
        "Block the sender domain and IP at the email gateway",
        "Alert all users who received the email",
        "Check if any user clicked the phishing link",
        "Run endpoint scan on machines that opened the email",
        "Report phishing campaign to threat intelligence feed"
    ],
    "Malware Detection": [
        "Immediately isolate the affected endpoint from the network",
        "Run a full malware scan using updated signatures",
        "Investigate the malware file hash in threat intelligence",
        "Check for lateral movement from the affected system",
        "Review all processes spawned before and after detection",
        "Preserve forensic evidence before remediation"
    ],
    "File Access": [
        "Verify if the file access was authorized",
        "Review the user's file access history",
        "Check if sensitive data was exfiltrated",
        "Audit file permissions on the accessed resource",
        "Enable DLP (Data Loss Prevention) alerts on sensitive paths",
        "Check destination IP if files were transferred externally"
    ],
    "Port Scan": [
        "Identify and block the scanning source IP",
        "Review firewall rules for exposed ports",
        "Check if any open ports are unintentionally exposed",
        "Look for follow-up intrusion attempts from the same source",
        "Enable IDS/IPS rules for port scan signatures",
        "Assess which services are externally visible"
    ],
    "Privilege Escalation": [
        "Immediately revoke escalated privileges",
        "Investigate how privilege escalation was achieved",
        "Review sudo/admin logs on the affected system",
        "Check for persistence mechanisms (cron jobs, startup scripts)",
        "Audit all actions performed with elevated privileges",
        "Patch the vulnerability used for escalation"
    ],
    "SQL Injection Attempt": [
        "Block the source IP at the WAF (Web Application Firewall)",
        "Review and sanitize affected application input fields",
        "Check database logs for any successful injection queries",
        "Assess if any data was extracted or modified",
        "Update application to use parameterized queries",
        "Run a web application vulnerability scan"
    ],
    "USB Device Connected": [
        "Identify and verify the USB device connected",
        "Scan the USB device for malware",
        "Check if any data was copied to or from the device",
        "Review endpoint USB access policy",
        "Disable USB ports if unauthorized usage is confirmed",
        "Alert the user's manager if policy was violated"
    ],
    "Login Success": [
        "Verify the login was from an expected location",
        "Check if the login time is unusual for the user",
        "Review subsequent actions taken after login",
        "Enable anomaly-based login alerts (geo-velocity)",
        "Cross-reference with threat intelligence for the source IP"
    ]
}

# ============================================================
# ADDITIONAL RECOMMENDATIONS BASED ON SEVERITY / IOC
# ============================================================

CRITICAL_ADDON = [
    "Escalate immediately to senior security analyst",
    "Consider activating Incident Response (IR) plan",
    "Notify management and CISO"
]

IOC_MATCHED_ADDON = [
    "Cross-reference IOC with threat intelligence platforms (VirusTotal, OTX)",
    "Share IOC details with SOC team for threat hunting",
    "Add IOC to SIEM block list"
]

HIGH_CVSS_ADDON = [
    "Prioritize patching the associated CVE immediately",
    "Check if other assets are affected by the same CVE"
]


def get_recommendations(event_type: str,
                        risk_class: str = "Medium",
                        ioc_match: bool = False,
                        cvss_score: float = 0.0,
                        mitre_technique: str = None) -> list:
    """
    Returns a list of actionable recommendations for a given event.

    Args:
        event_type   : Type of security event (e.g. 'Brute Force')
        risk_class   : Risk classification ('Low','Medium','Moderate','High','Critical')
        ioc_match    : Whether event matched a known IOC
        cvss_score   : CVSS score of associated vulnerability
        mitre_technique : MITRE ATT&CK technique ID (e.g. 'T1110')

    Returns:
        List of recommendation strings
    """
    # Base recommendations by event type
    recs = RECOMMENDATIONS.get(event_type, [
        "Investigate the event details and assess the impact",
        "Review related logs for additional context",
        "Escalate if the event cannot be explained"
    ])

    result = list(recs)  # copy

    # Add IOC-specific recommendations
    if ioc_match:
        result.extend(IOC_MATCHED_ADDON)

    # Add high CVSS recommendations
    if cvss_score and float(cvss_score) >= 8.0:
        result.extend(HIGH_CVSS_ADDON)

    # Add critical escalation recommendations
    if risk_class in ("Critical", "High"):
        result.extend(CRITICAL_ADDON)

    return result


def get_recommendations_for_incident(incident: dict) -> list:
    """
    Convenience wrapper — accepts an incident dict and returns recommendations.
    """
    return get_recommendations(
        event_type=incident.get("threat_type", ""),
        risk_class=incident.get("priority", "Medium"),
        ioc_match=incident.get("ioc_match", False),
        cvss_score=incident.get("cvss_score", 0.0),
        mitre_technique=incident.get("mitre_technique")
    )
