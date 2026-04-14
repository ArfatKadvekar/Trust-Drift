FEATURE_EXPLANATIONS = {
    "Bwd Avg Bytes/Bulk": "high volume of data per bulk transfer (backward)",
    "Bwd Avg Packets/Bulk": "frequent packet bursts in backward direction",
    "Fwd Avg Bulk Rate": "high forward data transfer rate",
    "Fwd Avg Bytes/Bulk": "large data chunks in forward direction",
    "Fwd Avg Packets/Bulk": "burst of packets in forward direction",

    "Bwd PSH Flags": "push flags in backward traffic (immediate sending)",
    "Fwd PSH Flags": "push flags in forward traffic (rapid sending)",
    "PSH Flag Count": "frequent push requests forcing immediate data transfer",

    "URG Flag Count": "urgent packets detected",
    "Bwd URG Flags": "urgent packets in backward traffic",
    "Fwd URG Flags": "urgent packets in forward traffic",

    "SYN Flag Count": "connection initiation spikes (possible scanning)",
    "RST Flag Count": "frequent connection resets",

    "CWE Flag Count": "network congestion control anomalies",
    "ECE Flag Count": "explicit congestion signals in traffic",
}


def get_risk_level(score):
    if score < 0.2:
        return "LOW"
    elif score < 0.5:
        return "MEDIUM"
    elif score < 0.8:
        return "HIGH"
    else:
        return "CRITICAL"


#  Attack inference (fixed)
def infer_attack(features):
    f_str = " ".join(features)

    if "SYN Flag" in f_str:
        return "Possible SYN Flood Attack"
    elif "Bulk" in f_str:
        return "Possible Data Exfiltration"
    elif "PSH" in f_str:
        return "High-speed data transmission anomaly"
    elif "URG" in f_str:
        return "Suspicious urgent packet behavior"
    else:
        return "Unknown anomaly pattern"


#  Smarter interpretation
def interpret_features(features):
    text = ""

    if any("Bulk" in f for f in features):
        text += "• Abnormal bulk data transfer detected\n"

    if any("PSH" in f for f in features):
        text += "• Rapid data transmission using push flags\n"

    if any("SYN" in f for f in features):
        text += "• Unusual connection initiation patterns\n"

    if any("RST" in f for f in features):
        text += "• Frequent connection resets observed\n"

    if any("URG" in f for f in features):
        text += "• Presence of urgent packet signals\n"

    if any(x in f for f in features for x in ["CWE", "ECE"]):
        text += "• Network congestion or control anomalies\n"

    return text

def generate_verdict(level, top_features):
    f_str = " ".join(top_features)

    if level == "CRITICAL":
        if "SYN" in f_str:
            return "Traffic strongly resembles a flooding attack with excessive connection requests."
        elif "Bulk" in f_str:
            return "Large-scale data transfer patterns suggest possible data exfiltration."
        elif "PSH" in f_str:
            return "Unusually fast data transmission indicates aggressive or automated activity."
        else:
            return "Traffic pattern is highly abnormal and likely malicious."

    elif level == "HIGH":
        if "RST" in f_str:
            return "Frequent connection resets indicate unstable or potentially malicious sessions."
        elif "URG" in f_str:
            return "Presence of urgent packets suggests irregular or manipulated traffic behavior."
        else:
            return "Traffic deviates significantly from normal patterns and may indicate an attack."

    elif level == "MEDIUM":
        if "Bulk" in f_str:
            return "Moderate irregularities in data transfer observed, could be unusual but not necessarily harmful."
        elif "PSH" in f_str:
            return "Slightly elevated transmission activity detected, worth monitoring."
        else:
            return "Traffic shows minor anomalies but remains within acceptable limits."

    else:  # LOW
        return "Traffic behavior is consistent with normal network activity."

def generate_explanation(severity, top_features, label=None):
    level = get_risk_level(severity)

    explanation = "\n" + "-"*40 + "\n"
    explanation += f"ALERT: {level} RISK NETWORK ACTIVITY\n\n"

    # Label
    if label is not None:
        explanation += f"Actual Label: {label}\n\n"

    # Why this label (feature interpretation)
    explanation += "Explanation:\n"

    if any("Bulk" in f for f in top_features):
        explanation += "- Abnormal bulk data transfer observed\n"

    if any("PSH" in f for f in top_features):
        explanation += "- Rapid data transmission using push flags\n"

    if any("SYN" in f for f in top_features):
        explanation += "- High number of connection initiation requests\n"

    if any("RST" in f for f in top_features):
        explanation += "- Frequent connection resets detected\n"

    if any("URG" in f for f in top_features):
        explanation += "- Presence of urgent packets in traffic\n"

    if any(x in f for f in top_features for x in ["CWE", "ECE"]):
        explanation += "- Network congestion or control anomalies detected\n"

    # Severity
    explanation += f"\nSeverity Score: {round(severity, 3)}\n"

    verdict = generate_verdict(level, top_features)

    explanation += "\nConclusion:\n"
    explanation += verdict + "\n"

    return explanation


#  Zone Mapping
def get_zone_info(trust_score):
    if trust_score > 0.8:
        return "Zone A — Full Access", "Full access allowed."
    elif trust_score > 0.4:
        return "Zone B — Drifting", "Multi-factor authentication required and traffic is being monitored."
    else:
        return "Zone C — Restricted", "Quarantine / Blocked. Connection terminated."


#  MITRE ATT&CK Playbook Generator (Hidden Mapping)
def generate_mitre_playbook(trust_score, diag):
    """
    Generates a formatted security playbook using existing model diagnostics.
    """
    severity = diag.get("severity_score", 0.0)
    top_features = diag.get("top_features", [])
    feat_errors = diag.get("feature_errors", [])
    ae_score = diag.get("ae_score", 0)
    if_score = diag.get("if_score", 0)

    driver = "Behavioral drift detected by Autoencoder (AE)" if ae_score >= if_score else "Structural outlier detected by Isolation Forest (IF)"

    # Confidence based on score intensity
    if severity > 0.8:
        confidence = "High"
    elif severity > 0.4:
        confidence = "Medium"
    else:
        confidence = "Low"

    # Zone and Action
    zone_str, system_action = get_zone_info(trust_score)

    # Attack Pattern and Analysis (Human-readable MITRE descriptors)
    f_str = " ".join(top_features).lower()
    
    if "syn" in f_str:
        pattern = "Digital Reconnaissance (Possible Port Scan)"
        analysis = ("The system detected a rapid-fire attempt to knock on multiple 'doors' (ports) of the network.\n"
                    "This behavior is often used by outsiders to find a way in, much like a person trying every door handle in a building.")
    elif "bulk" in f_str:
        pattern = "Unusual Data Movement (Possible Exfiltration)"
        analysis = ("A massive amount of data is moving in or out of the system in a very short time.\n"
                    "This doesn't match normal office behavior and could indicate someone is copying sensitive information or creating unauthorized backups.")
    elif "psh" in f_str or "rst" in f_str:
        pattern = "Aggressive Connection behavior (Signaling Anomaly)"
        analysis = ("The connection is sending 'urgent' signals or being forced to reset repeatedly.\n"
                    "This usually happens when an automated script is trying to push through traffic or bypass security filters.")
    else:
        pattern = "Atypical Network Activity"
        analysis = ("The system noticed a pattern of behavior that doesn't fit the 'normal' routine of this user or device.\n"
                    "While not definitely an attack, it's different enough to warrant a quick review.")

    # Key Evidence (Top 2 features)
    evidence_lines = []
    for i in range(min(2, len(top_features))):
        feat = top_features[i]
        err = feat_errors[i] if i < len(feat_errors) else 0.0
        norm_range = "0.0–0.10" if "flag" in feat.lower() else "0.0–0.30"
        evidence_lines.append(f"• {feat} → high ({err:.2f} vs normal {norm_range})")
    evidence = "\n".join(evidence_lines)

    # Assemble Box - Professional format
    box = (
        "=" * 70 + "\n" +
        "SUSPICIOUS TRAFFIC DETECTED" + "\n" +
        "=" * 70 + "\n\n" +
        f"Trust Score   : {trust_score:.2f} ({zone_str})\n" +
        f"Severity      : {severity:.2f}\n\n" +
        f"Attack Pattern:\n{pattern}\n\n" +
        f"Analysis:\n{analysis}\n\n" +
        f"Key Evidence:\n{evidence}\n\n" +
        f"Detection Source:\n{driver}\n\n" +
        f"Confidence:\n{confidence}\n\n" +
        f"System Action:\n{system_action}\n" +
        "=" * 70
    )

    return box

