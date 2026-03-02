"""LLM prompt templates for ThreatSignal AI."""
from __future__ import annotations

SYSTEM_PROMPT = """You are a cybersecurity risk analyst AI with expertise in threat intelligence.
You will receive:
1. An attack surface summary for a company's internet-facing infrastructure
2. Top similar historical breach cases with similarity scores
3. A time horizon in days

Your task: estimate the probability that this company will suffer a significant
cyber incident within the given time horizon.

IMPORTANT CALIBRATION GUIDELINES:
- Most companies, even with some exposure, have probability < 0.15 for a 30-day window
- Reserve HIGH probability (>0.35) for severely exposed or actively targeted organizations
- Reserve CRITICAL (>0.55) for organizations with multiple active CVEs and high-value profile
- A single CVE indicator does NOT automatically mean HIGH risk
- Consider industry, visibility, and attacker motivation

Return ONLY a valid JSON object with exactly these fields (no other text):
{
  "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "probability": <float 0.0 to 1.0>,
  "confidence": <float 0.0 to 1.0>,
  "main_drivers": [<string>, <string>, <string>],
  "explanation": <string, max 200 words>
}"""


def build_user_prompt(
    domain: str,
    horizon_days: int,
    snapshot_text: str,
    attack_surface_score: float,
    open_ports: list[int],
    cve_indicators: list[str],
    similar_incidents: list[dict],
) -> str:
    similar_section = ""
    for i, inc in enumerate(similar_incidents[:3], start=1):
        similar_section += (
            f"\n{i}. **{inc.get('title', 'Unknown')}** "
            f"(Similarity: {inc.get('similarity_score', 0):.2f})\n"
            f"   - Year: {inc.get('year', 'N/A')} | "
            f"Risk Level: {inc.get('risk_level', 'N/A').upper()}\n"
            f"   - Key factors: {', '.join(inc.get('key_factors', []))}\n"
        )

    if not similar_section:
        similar_section = "\nNo similar historical cases found in database.\n"

    cve_text = ", ".join(cve_indicators[:5]) if cve_indicators else "None detected"
    port_text = str(open_ports[:15]) if open_ports else "None"

    return f"""## Target Domain Analysis

**Domain:** {domain}
**Time Horizon:** {horizon_days} days
**Attack Surface Score:** {attack_surface_score}/10

### Attack Surface Summary
{snapshot_text}

**Open Ports:** {port_text}
**CVE Indicators:** {cve_text}

### Top Similar Historical Breaches
{similar_section}

### Your Task
Estimate the probability that {domain} will suffer a significant
cybersecurity incident (breach, ransomware, DDoS, data leak) within
the next {horizon_days} days.

Return ONLY the JSON object with risk_level, probability, confidence,
main_drivers, and explanation."""
