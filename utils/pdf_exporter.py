"""
ThreatTrack Executive PDF Exporter
Generates a polished, professional 1-page Executive Vulnerability & SLA Triage Brief
using fpdf2, summarizing fleet MTTR, severity distribution, and Top 5 high-risk nodes.
"""

from datetime import datetime
from typing import Dict, Any
import pandas as pd
from fpdf import FPDF


class ThreatTrackPDF(FPDF):
    def header(self):
        # Top banner background
        self.set_fill_color(15, 23, 42)  # Dark slate navy
        self.rect(0, 0, 210, 24, "F")

        # Top banner accent line
        self.set_fill_color(239, 68, 68)  # Critical Red accent line
        self.rect(0, 24, 210, 1.5, "F")

        # Header Title
        self.set_xy(12, 5)
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(255, 255, 255)
        self.cell(100, 8, "THREATTRACK // EXECUTIVE TRIAGE BRIEF", ln=0, align="L")

        # Security Classification & Date
        self.set_xy(110, 5)
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(248, 113, 113)
        self.cell(88, 5, "CONFIDENTIAL - SEC ENG ONLY", ln=1, align="R")

        self.set_xy(110, 11)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(203, 213, 225)
        gen_time = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
        self.cell(88, 5, f"Report Generated: {gen_time}", ln=1, align="R")

        self.ln(12)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10, f"ThreatTrack Security Intelligence Suite | Page {self.page_no()}", align="C")


def generate_executive_pdf(
    metrics: Dict[str, Any],
    top_5_df: pd.DataFrame,
    env_breakdown: pd.DataFrame,
) -> bytes:
    """
    Compiles an executive-grade PDF summary into raw bytes.
    """
    pdf = ThreatTrackPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Section 1: Executive Overview Title
    pdf.set_xy(12, 30)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 7, "1. Executive Fleet Health & SLA Compliance", ln=1)

    # 4 KPI Cards
    card_y = 38
    card_width = 44
    card_height = 20
    spacing = 3

    cards = [
        {"title": "ACTIVE BACKLOG", "val": str(metrics["active_backlog_count"]), "sub": f"{metrics['total_assets']} Assets Monitored", "color": (30, 41, 59)},
        {"title": "CRITICAL / HIGH", "val": f"{metrics['critical_count']} / {metrics['high_count']}", "sub": "CVSS >= 7.0 Backlog", "color": (185, 28, 28)},
        {"title": "SLA BREACHES", "val": str(metrics["breached_count"]), "sub": f"{metrics['at_risk_count']} Items At-Risk", "color": (220, 38, 38) if metrics["breached_count"] > 0 else (22, 101, 52)},
        {"title": "SLA COMPLIANCE", "val": f"{metrics['sla_compliance_pct']}%", "sub": f"Target: 95.0% | MTTR: {metrics['mttr_days']}d", "color": (3, 105, 161)},
    ]

    for idx, c in enumerate(cards):
        x = 12 + idx * (card_width + spacing)
        # Background
        pdf.set_fill_color(248, 250, 252)
        pdf.set_draw_color(226, 232, 240)
        pdf.rect(x, card_y, card_width, card_height, "DF")

        # Top Accent border
        pdf.set_fill_color(*c["color"])
        pdf.rect(x, card_y, card_width, 2, "F")

        # Card Title
        pdf.set_xy(x + 2, card_y + 3)
        pdf.set_font("Helvetica", "B", 7)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(card_width - 4, 4, c["title"], align="L")

        # Card Value
        pdf.set_xy(x + 2, card_y + 7)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(*c["color"])
        pdf.cell(card_width - 4, 6, c["val"], align="L")

        # Card Subtext
        pdf.set_xy(x + 2, card_y + 14)
        pdf.set_font("Helvetica", "", 6.5)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(card_width - 4, 4, c["sub"], align="L")

    # Section 2: Environment & Severity Breakdown
    pdf.set_xy(12, 64)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, "2. Environmental Scope & Severity Distribution", ln=1)

    # Sub-table: Environment Breakdown
    pdf.set_xy(12, 71)
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(241, 245, 249)
    pdf.set_draw_color(203, 213, 225)
    pdf.set_text_color(30, 41, 59)

    col_widths = [36, 28, 28, 30, 32, 32]
    headers = ["Environment", "Weight", "Total CVEs", "Breached", "Mean Risk", "Remediation SLA"]

    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 6, h, border=1, align="C", fill=True)
    pdf.ln()

    pdf.set_font("Helvetica", "", 8)
    for _, row in env_breakdown.iterrows():
        env_name = str(row["environment"])
        weight_str = f"x{row['asset_weight']:.1f}"
        total_vulns = str(int(row["total_vulns"]))
        breached_vulns = str(int(row["breached_vulns"]))
        mean_risk = f"{row['mean_risk']:.2f}"
        sla_window = "Critical: 7d | High: 30d"

        pdf.set_text_color(15, 23, 42)
        pdf.cell(col_widths[0], 5.5, f" {env_name}", border=1)
        pdf.cell(col_widths[1], 5.5, weight_str, border=1, align="C")
        pdf.cell(col_widths[2], 5.5, total_vulns, border=1, align="C")

        if int(breached_vulns) > 0:
            pdf.set_text_color(185, 28, 28)
            pdf.set_font("Helvetica", "B", 8)
        else:
            pdf.set_text_color(22, 101, 52)
            pdf.set_font("Helvetica", "", 8)

        pdf.cell(col_widths[3], 5.5, breached_vulns, border=1, align="C")
        pdf.set_text_color(15, 23, 42)
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(col_widths[4], 5.5, mean_risk, border=1, align="C")
        pdf.cell(col_widths[5], 5.5, sla_window, border=1, align="C")
        pdf.ln()

    # Section 3: Top 5 High-Risk Nodes
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, "3. Top 5 Prioritized High-Risk Nodes (Remediation Queue)", ln=1)

    top_cols = [22, 38, 22, 28, 16, 20, 18, 22]
    top_headers = ["Asset ID", "Asset Name", "Env", "CVE ID", "CVSS", "Risk Score", "Days Open", "SLA Status"]

    pdf.set_font("Helvetica", "B", 7.5)
    pdf.set_fill_color(224, 231, 255)
    pdf.set_text_color(30, 41, 59)
    for i, h in enumerate(top_headers):
        pdf.cell(top_cols[i], 6, h, border=1, align="C", fill=True)
    pdf.ln()

    pdf.set_font("Helvetica", "", 7.5)
    for _, row in top_5_df.iterrows():
        pdf.set_text_color(15, 23, 42)
        pdf.cell(top_cols[0], 5.5, f" {row['asset_id']}", border=1)
        pdf.cell(top_cols[1], 5.5, f" {row['asset_name'][:20]}", border=1)
        pdf.cell(top_cols[2], 5.5, str(row["environment"]), border=1, align="C")
        pdf.cell(top_cols[3], 5.5, str(row["cve_id"]), border=1, align="C")
        pdf.cell(top_cols[4], 5.5, f"{row['cvss_score']:.1f}", border=1, align="C")

        # Risk Score in bold
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(185, 28, 28)
        pdf.cell(top_cols[5], 5.5, f"{row['risk_score']:.1f}", border=1, align="C")

        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(top_cols[6], 5.5, f"{int(row['days_open'])}d", border=1, align="C")

        status_text = str(row["sla_status"])
        if status_text == "BREACHED":
            pdf.set_text_color(185, 28, 28)
            pdf.set_font("Helvetica", "B", 7.5)
        elif status_text == "AT RISK":
            pdf.set_text_color(180, 83, 9)
            pdf.set_font("Helvetica", "B", 7.5)
        else:
            pdf.set_text_color(22, 101, 52)
            pdf.set_font("Helvetica", "", 7.5)

        pdf.cell(top_cols[7], 5.5, status_text, border=1, align="C")
        pdf.ln()

    # Section 4: SecOps Operational Directives
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, "4. SecOps Mandates & Incident Remediation Playbook", ln=1)

    pdf.set_fill_color(248, 250, 252)
    pdf.set_draw_color(203, 213, 225)
    pdf.rect(12, pdf.get_y(), 186, 32, "DF")

    pdf.set_xy(14, pdf.get_y() + 2)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(51, 65, 85)
    directives = (
        "1. IMMEDIATE CONTAINMENT: Nodes flagged as 'BREACHED' with Contextual Risk >= 12.0 must undergo immediate "
        "network segmentation or emergency patching within the current 24-hour cycle.\n"
        "2. EXPLOIT MITIGATION: For assets with active public exploits (e.g. RCE, Auth Bypass), apply WAF/IPS signatures "
        "prior to upstream vendor binary deployments.\n"
        "3. AUDIT SIGN-OFF: The SecOps On-Call Engineer must verify SHA256 signatures of all staging-tested patches "
        "before production rollouts to maintain SOC2 / ISO-27001 SLA conformance."
    )
    pdf.multi_cell(182, 4.5, directives)

    # Sign-off box
    pdf.set_xy(12, 255)
    pdf.set_font("Helvetica", "I", 7.5)
    pdf.set_text_color(100, 116, 139)
    pdf.cell(90, 5, "Report Certified by: ThreatTrack Autonomous Risk Engine", ln=0)
    pdf.cell(96, 5, "CISO Governance Clearance: APPROVED", ln=1, align="R")

    return bytes(pdf.output())
