"""
ThreatTrack Risk & SLA Engine
Computes contextual risk scores, enforces SLA policies, and aggregates enterprise metrics.
"""

from typing import Dict, Any, List
import pandas as pd
import numpy as np

# Asset Criticality Weight Mappings
ASSET_WEIGHTS: Dict[str, float] = {
    "Production": 1.5,
    "Staging": 1.0,
    "Internal": 0.5,
}

# SLA Remediation Thresholds (in Calendar Days)
SLA_THRESHOLDS: Dict[str, int] = {
    "Critical": 7,    # CVSS 9.0 - 10.0
    "High": 30,       # CVSS 7.0 - 8.9
    "Medium": 60,     # CVSS 4.0 - 6.9
    "Low": 90,        # CVSS 0.1 - 3.9
}


def get_severity_tier(cvss_score: float) -> str:
    """Classify CVSS score into standard severity tier."""
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    else:
        return "Low"


def get_risk_tier(risk_score: float) -> str:
    """Classify contextual risk score into operational tiers."""
    if risk_score >= 12.0:
        return "Extreme"
    elif risk_score >= 8.0:
        return "High"
    elif risk_score >= 4.0:
        return "Moderate"
    else:
        return "Low"


def calculate_risk_score(cvss_score: float, environment: str) -> float:
    """
    Contextual Risk Score = CVSS Score * Asset Weight
    - Production: 1.5
    - Staging: 1.0
    - Internal: 0.5
    """
    weight = ASSET_WEIGHTS.get(environment, 1.0)
    return round(cvss_score * weight, 2)


def evaluate_sla(cvss_score: float, days_open: int, status: str) -> Dict[str, Any]:
    """
    Evaluate SLA target and compliance status based on CVSS score and aging.
    """
    severity = get_severity_tier(cvss_score)
    sla_target_days = SLA_THRESHOLDS[severity]
    remaining_days = sla_target_days - days_open

    if status == "Resolved":
        is_breached = days_open > sla_target_days
        sla_status = "RESOLVED"
    elif status == "Exception Approved":
        is_breached = False
        sla_status = "EXCEPTION"
    else:
        if days_open > sla_target_days:
            is_breached = True
            sla_status = "BREACHED"
        elif remaining_days <= max(2, int(sla_target_days * 0.25)):
            is_breached = False
            sla_status = "AT RISK"
        else:
            is_breached = False
            sla_status = "IN SLA"

    return {
        "severity": severity,
        "sla_target_days": sla_target_days,
        "remaining_days": remaining_days,
        "sla_status": sla_status,
        "is_breached": is_breached,
    }


def enrich_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """
    Vectorized computation of Contextual Risk, Severity, and SLA states
    over an input assets/vulnerabilities dataframe.
    """
    enriched = df.copy()

    # Asset Weight
    enriched["asset_weight"] = enriched["environment"].map(lambda env: ASSET_WEIGHTS.get(env, 1.0))

    # Contextual Risk Score
    enriched["risk_score"] = (enriched["cvss_score"] * enriched["asset_weight"]).round(2)
    enriched["risk_tier"] = enriched["risk_score"].map(get_risk_tier)

    # Severity Tier
    enriched["severity"] = enriched["cvss_score"].map(get_severity_tier)

    # SLA Target Days
    enriched["sla_target_days"] = enriched["severity"].map(lambda sev: SLA_THRESHOLDS[sev])

    # Remaining SLA Days
    enriched["remaining_days"] = enriched["sla_target_days"] - enriched["days_open"]

    # SLA Status & Breach Flag
    def _compute_row_sla(row):
        res = evaluate_sla(row["cvss_score"], row["days_open"], row["status"])
        return pd.Series([res["sla_status"], res["is_breached"]])

    sla_eval = enriched.apply(_compute_row_sla, axis=1)
    enriched["sla_status"] = sla_eval[0]
    enriched["is_breached"] = sla_eval[1]

    return enriched


def get_top_high_risk_nodes(df: pd.DataFrame, top_n: int = 5) -> pd.DataFrame:
    """
    Extract the top N highest contextual risk records across the fleet.
    Sorted primarily by risk_score descending, then cvss_score descending.
    """
    return df.sort_values(
        by=["risk_score", "cvss_score", "days_open"],
        ascending=[False, False, False]
    ).head(top_n).copy()


def compute_metrics(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Calculates executive CISO & SecOps KPIs across the provided dataframe.
    """
    total_records = len(df)
    if total_records == 0:
        return {
            "total_assets": 0,
            "total_vulnerabilities": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "breached_count": 0,
            "at_risk_count": 0,
            "in_sla_count": 0,
            "resolved_count": 0,
            "active_backlog_count": 0,
            "sla_compliance_pct": 100.0,
            "mttr_days": 0.0,
            "avg_days_open_backlog": 0.0,
            "avg_risk_score": 0.0,
        }

    total_assets = df["asset_id"].nunique()
    total_vulns = total_records

    # Severities
    crit_count = int((df["severity"] == "Critical").sum())
    high_count = int((df["severity"] == "High").sum())
    med_count = int((df["severity"] == "Medium").sum())
    low_count = int((df["severity"] == "Low").sum())

    # Status counts
    resolved_mask = df["status"] == "Resolved"
    active_mask = ~resolved_mask

    resolved_count = int(resolved_mask.sum())
    active_count = int(active_mask.sum())

    breached_count = int((active_mask & (df["sla_status"] == "BREACHED")).sum())
    at_risk_count = int((active_mask & (df["sla_status"] == "AT RISK")).sum())
    in_sla_count = int((active_mask & (df["sla_status"] == "IN SLA")).sum())

    # SLA Compliance % for active queue
    if active_count > 0:
        sla_compliance_pct = round(((active_count - breached_count) / active_count) * 100, 1)
        avg_days_open_backlog = round(float(df[active_mask]["days_open"].mean()), 1)
    else:
        sla_compliance_pct = 100.0
        avg_days_open_backlog = 0.0

    # MTTR for resolved
    if resolved_count > 0:
        mttr_days = round(float(df[resolved_mask]["days_open"].mean()), 1)
    else:
        mttr_days = 0.0

    avg_risk_score = round(float(df["risk_score"].mean()), 2)

    return {
        "total_assets": total_assets,
        "total_vulnerabilities": total_vulns,
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "breached_count": breached_count,
        "at_risk_count": at_risk_count,
        "in_sla_count": in_sla_count,
        "resolved_count": resolved_count,
        "active_backlog_count": active_count,
        "sla_compliance_pct": sla_compliance_pct,
        "mttr_days": mttr_days,
        "avg_days_open_backlog": avg_days_open_backlog,
        "avg_risk_score": avg_risk_score,
    }
