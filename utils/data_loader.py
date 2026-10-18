"""
ThreatTrack Data Loader
Generates and provides a deterministic seed catalog of enterprise infrastructure assets
mapped against realistic CVE vulnerabilities across Production, Staging, and Internal environments.
"""

import random
from datetime import datetime, timedelta
from typing import Optional
import pandas as pd

# Canonical Realistic CVEs Pool
CVE_CATALOG = [
    {
        "cve_id": "CVE-2024-3094",
        "cve_title": "XZ Utils Backdoor (SSH Authentication Bypass)",
        "base_cvss": 10.0,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "liblzma / OpenSSH",
    },
    {
        "cve_id": "CVE-2023-44487",
        "cve_title": "HTTP/2 Rapid Reset Distributed Denial of Service",
        "base_cvss": 7.5,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "HTTP/2 Reverse Proxy",
    },
    {
        "cve_id": "CVE-2024-21626",
        "cve_title": "runc Container Breakout via Leaky File Descriptors",
        "base_cvss": 8.6,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "runc / containerd",
    },
    {
        "cve_id": "CVE-2023-48795",
        "cve_title": "Terrapin SSH Protocol Extension Negotiation Downgrade",
        "base_cvss": 5.9,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "OpenSSH Client/Server",
    },
    {
        "cve_id": "CVE-2024-3400",
        "cve_title": "PAN-OS GlobalProtect Command Injection Vulnerability",
        "base_cvss": 10.0,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "GlobalProtect Gateway",
    },
    {
        "cve_id": "CVE-2024-1709",
        "cve_title": "ConnectWise ScreenConnect Authentication Bypass",
        "base_cvss": 10.0,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Remote Access Daemon",
    },
    {
        "cve_id": "CVE-2023-38606",
        "cve_title": "Kernel Memory Corruption / Privilege Escalation",
        "base_cvss": 7.8,
        "exploit_available": False,
        "patch_available": True,
        "affected_component": "Linux Kernel 5.15",
    },
    {
        "cve_id": "CVE-2024-38077",
        "cve_title": "Windows Remote Desktop Licensing Service RCE (MadLicence)",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "RDP Licensing Service",
    },
    {
        "cve_id": "CVE-2023-22515",
        "cve_title": "Confluence Data Center Privilege Escalation",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Atlassian Web Suite",
    },
    {
        "cve_id": "CVE-2023-34362",
        "cve_title": "MOVEit Transfer SQL Injection Vulnerability",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Managed File Transfer",
    },
    {
        "cve_id": "CVE-2024-0012",
        "cve_title": "PAN-OS Management Interface Authentication Bypass",
        "base_cvss": 9.3,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Admin Web Interface",
    },
    {
        "cve_id": "CVE-2023-20198",
        "cve_title": "Cisco IOS XE Web UI Privilege Escalation",
        "base_cvss": 10.0,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Network Router WebUI",
    },
    {
        "cve_id": "CVE-2023-4911",
        "cve_title": "Looney Tunables glibc ld.so Buffer Overflow",
        "base_cvss": 7.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "glibc runtime",
    },
    {
        "cve_id": "CVE-2024-23897",
        "cve_title": "Jenkins CLI Arbitrary File Read Vulnerability",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Jenkins Automation Server",
    },
    {
        "cve_id": "CVE-2023-29357",
        "cve_title": "Microsoft SharePoint Server Privilege Escalation",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "SharePoint Internal Farm",
    },
    {
        "cve_id": "CVE-2024-27348",
        "cve_title": "Apache HugeGraph Database Remote Code Execution",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Graph Database Engine",
    },
    {
        "cve_id": "CVE-2023-46604",
        "cve_title": "Apache ActiveMQ OpenWire Protocol RCE",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Message Broker ActiveMQ",
    },
    {
        "cve_id": "CVE-2024-24919",
        "cve_title": "Check Point Security Gateway Information Disclosure",
        "base_cvss": 8.6,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "VPN Remote Access Blade",
    },
    {
        "cve_id": "CVE-2023-2825",
        "cve_title": "GitLab Community Edition Path Traversal",
        "base_cvss": 6.5,
        "exploit_available": False,
        "patch_available": True,
        "affected_component": "GitLab CI Server",
    },
    {
        "cve_id": "CVE-2023-32315",
        "cve_title": "Openfire Administrative Console Auth Bypass",
        "base_cvss": 7.5,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "XMPP Chat Gateway",
    },
    {
        "cve_id": "CVE-2024-4577",
        "cve_title": "PHP CGI Argument Injection Remote Code Execution",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Legacy PHP Runtime",
    },
    {
        "cve_id": "CVE-2023-38545",
        "cve_title": "curl SOCKS5 Heap Buffer Overflow",
        "base_cvss": 9.8,
        "exploit_available": False,
        "patch_available": True,
        "affected_component": "libcurl Network Utility",
    },
    {
        "cve_id": "CVE-2024-21413",
        "cve_title": "Microsoft Outlook NTLM Hash Disclosure (MonikerLink)",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Corporate Mail Client",
    },
    {
        "cve_id": "CVE-2023-36884",
        "cve_title": "Office & Windows HTML RCE Vulnerability (RomCom)",
        "base_cvss": 8.3,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Workstation Office Engine",
    },
    {
        "cve_id": "CVE-2023-23397",
        "cve_title": "Outlook Elevation of Privilege Zero-Click NetNTLM",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "MAPI Protocol Stack",
    },
    {
        "cve_id": "CVE-2024-6387",
        "cve_title": "regreSSHion OpenSSH Server Remote Code Execution",
        "base_cvss": 8.1,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "OpenSSH Daemon sshd",
    },
    {
        "cve_id": "CVE-2023-32439",
        "cve_title": "WebKit Memory Corruption Arbitrary Code Execution",
        "base_cvss": 8.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Embedded WebKit Engine",
    },
    {
        "cve_id": "CVE-2024-20353",
        "cve_title": "Cisco Adaptive Security Appliance Denial of Service",
        "base_cvss": 8.6,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Cisco ASA Firewall Core",
    },
    {
        "cve_id": "CVE-2023-28771",
        "cve_title": "Zyxel IKE Packet OS Command Injection",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Branch Office VPN",
    },
    {
        "cve_id": "CVE-2024-30078",
        "cve_title": "Windows Wi-Fi Driver Remote Code Execution",
        "base_cvss": 8.8,
        "exploit_available": False,
        "patch_available": True,
        "affected_component": "WLAN NIC Driver",
    },
    {
        "cve_id": "CVE-2024-1086",
        "cve_title": "Linux Kernel Netfilter Privilege Escalation",
        "base_cvss": 7.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "nftables Subsystem",
    },
    {
        "cve_id": "CVE-2023-38035",
        "cve_title": "MobileIron Sentry Authentication Bypass",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "MDM Mobile Gateway",
    },
    {
        "cve_id": "CVE-2024-21338",
        "cve_title": "Windows Kernel AppLocker Elevation of Privilege",
        "base_cvss": 7.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "AppLocker Kernel Driver",
    },
    {
        "cve_id": "CVE-2023-24489",
        "cve_title": "Citrix ShareFile StorageZones Unauthenticated RCE",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "ShareFile Controller",
    },
    {
        "cve_id": "CVE-2023-3519",
        "cve_title": "NetScaler ADC & Gateway Unauthenticated RCE",
        "base_cvss": 9.8,
        "exploit_available": True,
        "patch_available": True,
        "affected_component": "Citrix ADC Appliance",
    },
]

ASSET_TEMPLATES = [
    {"name": "k8s-ingress-prod-01", "env": "Production", "team": "Platform Eng", "ip": "10.0.12.14"},
    {"name": "payments-api-gateway", "env": "Production", "team": "Core Payments", "ip": "10.0.15.22"},
    {"name": "auth-vault-primary", "env": "Production", "team": "SecOps", "ip": "10.0.2.5"},
    {"name": "customer-db-aurora-rw", "env": "Production", "team": "Data Infra", "ip": "10.0.8.88"},
    {"name": "checkout-service-worker-01", "env": "Production", "team": "Core Payments", "ip": "10.0.18.31"},
    {"name": "fraud-detection-model-host", "env": "Production", "team": "AI & Risk", "ip": "10.0.19.4"},
    {"name": "cdn-origin-edge-cache", "env": "Production", "team": "Platform Eng", "ip": "10.0.5.11"},
    {"name": "redis-session-cluster-node1", "env": "Production", "team": "Platform Eng", "ip": "10.0.9.101"},
    {"name": "kafka-event-broker-prod-01", "env": "Production", "team": "Data Infra", "ip": "10.0.24.12"},
    {"name": "graphql-federation-gateway", "env": "Production", "team": "Frontend Platform", "ip": "10.0.14.77"},
    {"name": "corp-vpn-concentrator-east", "env": "Production", "team": "IT Infrastructure", "ip": "172.16.1.1"},
    {"name": "active-directory-pdc", "env": "Production", "team": "Identity & Access", "ip": "172.16.2.10"},
    {"name": "billing-invoice-daemon", "env": "Production", "team": "Finance Systems", "ip": "10.0.33.15"},
    {"name": "notification-dispatch-sms", "env": "Production", "team": "Messaging", "ip": "10.0.40.8"},
    {"name": "search-opensearch-cluster-01", "env": "Production", "team": "Search Eng", "ip": "10.0.55.9"},
    {"name": "stg-k8s-api-server", "env": "Staging", "team": "Platform Eng", "ip": "10.100.1.2"},
    {"name": "stg-payments-sandbox-node", "env": "Staging", "team": "Core Payments", "ip": "10.100.12.8"},
    {"name": "stg-auth-keycloak-test", "env": "Staging", "team": "SecOps", "ip": "10.100.4.15"},
    {"name": "stg-analytics-pipeline-worker", "env": "Staging", "team": "Data Infra", "ip": "10.100.22.90"},
    {"name": "stg-customer-portal-web", "env": "Staging", "team": "Frontend Platform", "ip": "10.100.14.33"},
    {"name": "stg-kafka-broker-01", "env": "Staging", "team": "Data Infra", "ip": "10.100.25.10"},
    {"name": "stg-model-validation-gpu", "env": "Staging", "team": "AI & Risk", "ip": "10.100.30.55"},
    {"name": "stg-external-webhook-relay", "env": "Staging", "team": "Platform Eng", "ip": "10.100.8.21"},
    {"name": "stg-reporting-api-service", "env": "Staging", "team": "Finance Systems", "ip": "10.100.19.12"},
    {"name": "stg-cache-redis-memtier", "env": "Staging", "team": "Platform Eng", "ip": "10.100.9.44"},
    {"name": "dev-jenkins-runner-linux-01", "env": "Internal", "team": "DevOps", "ip": "192.168.10.101"},
    {"name": "corp-gitlab-server-ce", "env": "Internal", "team": "DevOps", "ip": "192.168.10.50"},
    {"name": "internal-wiki-confluence", "env": "Internal", "team": "Corporate IT", "ip": "192.168.20.14"},
    {"name": "monitoring-prometheus-ha", "env": "Internal", "team": "SRE & Observability", "ip": "192.168.30.5"},
    {"name": "elk-logging-indexer-corp", "env": "Internal", "team": "SecOps", "ip": "192.168.30.22"},
    {"name": "developer-bastion-ssh-gw", "env": "Internal", "team": "SecOps", "ip": "192.168.1.15"},
    {"name": "jira-issue-tracker-app", "env": "Internal", "team": "Corporate IT", "ip": "192.168.20.15"},
    {"name": "corp-sonarqube-scanner", "env": "Internal", "team": "Security Eng", "ip": "192.168.15.8"},
    {"name": "artifactory-docker-registry", "env": "Internal", "team": "DevOps", "ip": "192.168.12.19"},
    {"name": "it-helpdesk-ticketing", "env": "Internal", "team": "Corporate IT", "ip": "192.168.25.4"},
]

STATUS_CHOICES = ["Open", "In Triage", "Remediation In Progress", "Resolved", "Exception Approved"]
STATUS_WEIGHTS = [0.45, 0.20, 0.15, 0.15, 0.05]


def generate_mock_catalog(count: int = 100, seed: int = 42) -> pd.DataFrame:
    """
    Generate exactly `count` localized static seed assets mapped to CVEs.
    Deterministic across identical seeds.
    """
    rng = random.Random(seed)
    records = []
    base_date = datetime(2026, 10, 15)

    for i in range(1, count + 1):
        # Pick template or synthesize consistent naming
        template_idx = (i - 1) % len(ASSET_TEMPLATES)
        template = ASSET_TEMPLATES[template_idx]

        # Environmental distribution balance
        # If count > len(ASSET_TEMPLATES), add index suffix
        suffix = f"-{(i - 1) // len(ASSET_TEMPLATES) + 1:02d}" if count > len(ASSET_TEMPLATES) else ""
        asset_name = f"{template['name']}{suffix}"
        asset_id = f"AST-{template['env'][:4].upper()}-{i:03d}"

        # Assign CVE from catalog with slight CVSS jitter for realistic diversity (1.0 - 10.0)
        cve_template = rng.choice(CVE_CATALOG)
        cve_id = cve_template["cve_id"]
        cve_title = cve_template["cve_title"]
        component = cve_template["affected_component"]

        # Jitter CVSS while maintaining realistic range [1.0, 10.0]
        score_offset = rng.choice([-0.4, -0.2, 0.0, 0.1, 0.2])
        cvss_score = round(max(1.0, min(10.0, cve_template["base_cvss"] + score_offset)), 1)

        # Elapsed days open (realistic distribution: 2 to 75 days)
        # Weight towards days that test SLA thresholds (around 7 and 30 days)
        if cvss_score >= 9.0:
            # Critical: Some overdue (> 7 days), some fresh (< 7 days)
            days_open = rng.choice([2, 4, 6, 8, 11, 14, 21, 28, 45])
        elif cvss_score >= 7.0:
            # High: Some overdue (> 30 days), some fresh (< 30 days)
            days_open = rng.choice([5, 12, 19, 26, 33, 42, 58, 65])
        else:
            days_open = rng.randint(4, 75)

        discovered_date = (base_date - timedelta(days=days_open)).strftime("%Y-%m-%d")

        status = rng.choices(STATUS_CHOICES, weights=STATUS_WEIGHTS, k=1)[0]
        exploit_available = cve_template["exploit_available"] or rng.random() < 0.25
        patch_available = cve_template["patch_available"] or rng.random() < 0.85

        records.append({
            "asset_id": asset_id,
            "asset_name": asset_name,
            "environment": template["env"],
            "owner_team": template["team"],
            "ip_address": template["ip"],
            "cve_id": cve_id,
            "cve_title": cve_title,
            "affected_component": component,
            "cvss_score": cvss_score,
            "discovered_date": discovered_date,
            "days_open": days_open,
            "status": status,
            "exploit_available": exploit_available,
            "patch_available": patch_available,
        })

    return pd.DataFrame(records)


def load_dataset(count: int = 100, seed: int = 42) -> pd.DataFrame:
    """
    Public entry point to retrieve the seed catalog.
    """
    return generate_mock_catalog(count=count, seed=seed)
