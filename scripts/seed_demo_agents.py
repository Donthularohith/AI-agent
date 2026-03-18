"""
Seed Demo Agents — Populate the registry with 20 realistic healthcare agents
and simulate complex governance scenarios (suspensions, policy checks, audits).

Run: python -m scripts.seed_demo_agents
"""

import asyncio
import httpx
import random
from datetime import datetime, timezone, timedelta

API_URL = "http://localhost:8080"

DEMO_AGENTS = [
    # ── EMR / Clinical ──
    {"name":"emr-patient-reader","version":"1.0.0","owner_email":"rohith.donthula@bytewave.com",
     "purpose":"Read patient demographics and lab results from EMR for clinical decision support workflows",
     "days":90,"tools":["mcp://emr/patient/read","mcp://emr/labs/query","mcp://emr/demographics/search"],
     "resources":["emr:patients:demographics:*","emr:patients:labs:*"],
     "depth":1,"ttl":900,"threshold":-0.3,"tags":["HIPAA"]},

    {"name":"clinical-summarizer","version":"1.3.0","owner_email":"rohith.donthula@bytewave.com",
     "purpose":"Generate clinical summaries from patient records using LLM for physician review",
     "days":60,"tools":["mcp://emr/patient/read","mcp://emr/notes/read","mcp://llm/summarize"],
     "resources":["emr:patients:demographics:*","emr:patients:notes:*","emr:patients:labs:*"],
     "depth":2,"ttl":1200,"threshold":-0.3,"tags":["HIPAA"]},

    {"name":"emr-notes-writer","version":"2.0.1","owner_email":"dr.adams@bytewave.com",
     "purpose":"Transcribe and write clinical encounter notes from voice dictation into EMR system",
     "days":180,"tools":["mcp://emr/notes/write","mcp://emr/notes/read","mcp://speech/transcribe"],
     "resources":["emr:patients:notes:*","emr:patients:encounters:*"],
     "depth":0,"ttl":600,"threshold":-0.25,"tags":["HIPAA"]},

    {"name":"vitals-monitor-agent","version":"1.2.0","owner_email":"icu.systems@bytewave.com",
     "purpose":"Continuous monitoring of ICU patient vitals with automated alert escalation for critical values",
     "days":365,"tools":["mcp://emr/vitals/read","mcp://emr/vitals/stream","mcp://notifications/critical"],
     "resources":["emr:patients:vitals:*","notifications:critical:*"],
     "depth":0,"ttl":300,"threshold":-0.15,"tags":["HIPAA"]},

    # ── Pharmacy ──
    {"name":"prescription-validator","version":"1.0.0","owner_email":"mike.chen@bytewave.com",
     "purpose":"Validate prescription orders against drug interaction databases and formulary",
     "days":365,"tools":["mcp://pharmacy/drugs/lookup","mcp://pharmacy/interactions/check","mcp://pharmacy/formulary/verify"],
     "resources":["pharmacy:drugs:*","pharmacy:interactions:*","pharmacy:formulary:*"],
     "depth":0,"ttl":300,"threshold":-0.35,"tags":["HIPAA"]},

    {"name":"medication-reconciler","version":"1.4.0","owner_email":"pharmacy.ops@bytewave.com",
     "purpose":"Reconcile patient medication lists across care transitions to prevent duplicate or conflicting prescriptions",
     "days":180,"tools":["mcp://pharmacy/medications/list","mcp://pharmacy/medications/reconcile","mcp://emr/patient/read"],
     "resources":["pharmacy:medications:*","emr:patients:medications:*"],
     "depth":1,"ttl":600,"threshold":-0.3,"tags":["HIPAA"]},

    # ── Billing / Finance ──
    {"name":"claims-processor","version":"2.1.0","owner_email":"sarah.johnson@bytewave.com",
     "purpose":"Automated processing and validation of insurance claims with ICD-10 code verification",
     "days":180,"tools":["mcp://billing/claims/submit","mcp://billing/claims/validate","mcp://billing/icd10/lookup"],
     "resources":["billing:claims:*","billing:icd10:codes:*"],
     "depth":0,"ttl":600,"threshold":-0.25,"tags":["HIPAA","PCI"]},

    {"name":"payment-gateway-agent","version":"1.8.0","owner_email":"finance@bytewave.com",
     "purpose":"Process patient co-pays, insurance reimbursements, and payment plan management",
     "days":365,"tools":["mcp://payments/process","mcp://payments/refund","mcp://billing/invoice/generate"],
     "resources":["payments:transactions:*","billing:invoices:*","billing:insurance:*"],
     "depth":0,"ttl":300,"threshold":-0.2,"tags":["PCI","HIPAA","SOX"]},

    {"name":"denial-appeals-bot","version":"1.1.0","owner_email":"revenue.cycle@bytewave.com",
     "purpose":"Automated insurance denial review, appeal letter generation, and resubmission tracking",
     "days":120,"tools":["mcp://billing/denials/read","mcp://billing/appeals/submit","mcp://llm/generate"],
     "resources":["billing:denials:*","billing:appeals:*"],
     "depth":1,"ttl":900,"threshold":-0.3,"tags":["HIPAA","PCI"]},

    # ── Imaging / Radiology ──
    {"name":"radiology-ai-reader","version":"3.2.1","owner_email":"dr.patel@radiology.cerner.com",
     "purpose":"AI-assisted radiology image analysis for CT, MRI, and X-ray with DICOM integration",
     "days":120,"tools":["mcp://imaging/dicom/read","mcp://imaging/ai/analyze","mcp://imaging/report/generate"],
     "resources":["imaging:dicom:*","imaging:reports:*","emr:patients:imaging:*"],
     "depth":1,"ttl":1800,"threshold":-0.2,"tags":["HIPAA","SOX"]},

    {"name":"pathology-slide-analyzer","version":"2.0.0","owner_email":"pathology@bytewave.com",
     "purpose":"Digital pathology slide analysis using deep learning for cancer screening and tumor grading",
     "days":180,"tools":["mcp://pathology/slides/read","mcp://pathology/ai/classify","mcp://pathology/report/create"],
     "resources":["pathology:slides:*","pathology:reports:*"],
     "depth":0,"ttl":1200,"threshold":-0.15,"tags":["HIPAA"]},

    # ── Operations / Scheduling ──
    {"name":"appointment-scheduler","version":"2.0.0","owner_email":"ops.team@bytewave.com",
     "purpose":"Automated patient appointment scheduling, rescheduling, and cancellation management",
     "days":365,"tools":["mcp://scheduling/book","mcp://scheduling/cancel","mcp://scheduling/availability"],
     "resources":["scheduling:appointments:*","scheduling:providers:*"],
     "depth":0,"ttl":600,"threshold":-0.4,"tags":["HIPAA"]},

    {"name":"bed-management-agent","version":"1.0.0","owner_email":"hospital.ops@bytewave.com",
     "purpose":"Real-time bed availability tracking, patient assignment, and discharge coordination",
     "days":365,"tools":["mcp://beds/status/read","mcp://beds/assign","mcp://beds/discharge"],
     "resources":["hospital:beds:*","hospital:wards:*"],
     "depth":0,"ttl":300,"threshold":-0.3,"tags":["HIPAA"]},

    # ── Notifications / Alerts ──
    {"name":"lab-results-notifier","version":"1.5.0","owner_email":"rohith.donthula@bytewave.com",
     "purpose":"Monitor lab result completion events and notify physicians of critical values in real-time",
     "days":90,"tools":["mcp://emr/labs/read","mcp://notifications/send","mcp://emr/provider/lookup"],
     "resources":["emr:patients:labs:*","notifications:alerts:*"],
     "depth":1,"ttl":300,"threshold":-0.3,"tags":["HIPAA"]},

    # ── Compliance / Security ──
    {"name":"compliance-auditor","version":"1.0.0","owner_email":"compliance@bytewave.com",
     "purpose":"Automated HIPAA compliance scanning and audit report generation across all agent activities",
     "days":365,"tools":["mcp://audit/logs/read","mcp://audit/reports/generate","mcp://compliance/scan"],
     "resources":["audit:logs:*","compliance:reports:*","compliance:policies:*"],
     "depth":3,"ttl":3600,"threshold":-0.15,"tags":["HIPAA","SOX","GDPR"]},

    {"name":"admin-access-controller","version":"1.0.0","owner_email":"security@bytewave.com",
     "purpose":"Manage administrative access control, role provisioning, and emergency break-glass procedures",
     "days":90,"tools":["mcp://admin/roles/manage","mcp://admin/access/grant","mcp://admin/access/revoke","mcp://admin/breakglass/activate"],
     "resources":["admin:roles:*","admin:access:*","admin:breakglass:*"],
     "depth":0,"ttl":180,"threshold":-0.1,"tags":["HIPAA","SOX","GDPR"]},

    {"name":"threat-detection-agent","version":"2.1.0","owner_email":"soc@bytewave.com",
     "purpose":"Real-time threat detection across agent network using behavioral analysis and anomaly scoring",
     "days":365,"tools":["mcp://security/threat/detect","mcp://security/alert/create","mcp://agents/suspend"],
     "resources":["security:threats:*","security:alerts:*","agents:all:status"],
     "depth":2,"ttl":120,"threshold":-0.05,"tags":["HIPAA","SOX"]},

    # ── Telehealth ──
    {"name":"telemedicine-assistant","version":"2.4.0","owner_email":"telehealth@bytewave.com",
     "purpose":"Support telemedicine video consultations with real-time patient chart access and note-taking",
     "days":180,"tools":["mcp://emr/patient/read","mcp://telehealth/session/manage","mcp://emr/notes/write"],
     "resources":["emr:patients:demographics:*","emr:patients:notes:*","telehealth:sessions:*"],
     "depth":1,"ttl":900,"threshold":-0.3,"tags":["HIPAA"]},

    # ── Care Coordination ──
    {"name":"discharge-planner","version":"1.1.0","owner_email":"care.coordination@bytewave.com",
     "purpose":"Generate discharge plans, medication reconciliation lists, and follow-up appointment schedules",
     "days":120,"tools":["mcp://emr/patient/read","mcp://emr/medications/list","mcp://scheduling/book","mcp://emr/discharge/create"],
     "resources":["emr:patients:*","emr:medications:*","scheduling:appointments:*"],
     "depth":2,"ttl":1200,"threshold":-0.25,"tags":["HIPAA"]},

    {"name":"care-gap-identifier","version":"1.0.0","owner_email":"population.health@bytewave.com",
     "purpose":"Identify gaps in preventive care by analyzing patient records against clinical guidelines",
     "days":365,"tools":["mcp://emr/patient/read","mcp://guidelines/check","mcp://notifications/send"],
     "resources":["emr:patients:*","guidelines:preventive:*"],
     "depth":1,"ttl":1800,"threshold":-0.3,"tags":["HIPAA","GDPR"]},
]


def build_agent(a):
    return {
        "name": a["name"], "version": a["version"], "owner_email": a["owner_email"],
        "purpose": a["purpose"],
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=a["days"])).isoformat(),
        "allowed_tools": a["tools"], "allowed_resources": a["resources"],
        "max_delegation_depth": a["depth"], "credential_ttl_seconds": a["ttl"],
        "anomaly_threshold": a["threshold"], "compliance_tags": a["tags"],
    }


async def seed_agents():
    """Register agents, then simulate complex governance events."""
    async with httpx.AsyncClient(base_url=API_URL, timeout=15) as client:
        print(f"\n{'='*60}")
        print("  🚀 Seeding 20 Healthcare AI Agents")
        print(f"{'='*60}\n")

        agent_ids = {}
        for a in DEMO_AGENTS:
            payload = build_agent(a)
            try:
                r = await client.post("/agents", json=payload)
                if r.status_code == 201:
                    d = r.json()
                    agent_ids[a["name"]] = d["agent_id"]
                    print(f"  ✅ {a['name']:30s} [{', '.join(a['tags'])}]")
                elif r.status_code == 400 and "already exists" in r.text:
                    print(f"  ⏩ {a['name']:30s} (exists)")
                    # Try to get existing agent ID
                    lr = await client.get("/agents?page_size=100")
                    if lr.status_code == 200:
                        for ag in lr.json().get("agents", []):
                            if ag["name"] == a["name"]:
                                agent_ids[a["name"]] = ag["agent_id"]
                else:
                    print(f"  ❌ {a['name']:30s} {r.status_code}: {r.text[:80]}")
            except Exception as e:
                print(f"  ❌ {a['name']:30s} Error: {e}")

        total_r = await client.get("/agents")
        total = total_r.json().get("total", 0) if total_r.status_code == 200 else "?"
        print(f"\n  📊 Total agents in registry: {total}")

        # ── Simulate Complex Governance Scenarios ──
        print(f"\n{'='*60}")
        print("  ⚡ Simulating Governance Scenarios")
        print(f"{'='*60}\n")

        # Scenario 1: Suspend a rogue agent
        if "denial-appeals-bot" in agent_ids:
            aid = agent_ids["denial-appeals-bot"]
            r = await client.post(f"/agents/{aid}/suspend")
            if r.status_code == 200:
                print("  🔴 SCENARIO 1: denial-appeals-bot SUSPENDED")
                print("     Reason: Detected unauthorized access to billing:denials:* outside business hours")
            else:
                print(f"  ⚠️  Suspend failed: {r.status_code}")

        # Scenario 2: Suspend threat actor
        if "bed-management-agent" in agent_ids:
            aid = agent_ids["bed-management-agent"]
            r = await client.post(f"/agents/{aid}/suspend")
            if r.status_code == 200:
                print("  🔴 SCENARIO 2: bed-management-agent SUSPENDED")
                print("     Reason: Anomalous bed reassignment pattern — potential data exfiltration")

        # Scenario 3: Policy evaluation tests
        policies_to_test = []
        if "emr-patient-reader" in agent_ids:
            policies_to_test.append(("emr-patient-reader", "mcp://emr/patient/read", "emr:patients:demographics:*"))
            policies_to_test.append(("emr-patient-reader", "mcp://admin/access/grant", "admin:access:*"))  # Should DENY
        if "claims-processor" in agent_ids:
            policies_to_test.append(("claims-processor", "mcp://billing/claims/submit", "billing:claims:*"))
            policies_to_test.append(("claims-processor", "mcp://emr/patient/read", "emr:patients:*"))  # Should DENY

        if policies_to_test:
            print(f"\n  ⚡ SCENARIO 3: Policy Decision Tests")
            for name, tool, resource in policies_to_test:
                aid = agent_ids[name]
                r = await client.post("/policy/decide", json={
                    "agent_id": aid, "action": "tool_call",
                    "tool_uri": tool, "resource": resource, "delegation_depth": 0
                })
                if r.status_code == 200:
                    d = r.json()
                    allowed = d.get("allow", False)
                    icon = "✅" if allowed else "❌"
                    print(f"     {icon} {name} → {tool.split('/')[-1]}: {'ALLOWED' if allowed else 'DENIED'}")

        # Scenario 4: Credential lifecycle
        if "radiology-ai-reader" in agent_ids:
            aid = agent_ids["radiology-ai-reader"]
            r = await client.post(f"/credentials/issue", json={"agent_id": aid})
            if r.status_code in (200, 201):
                cred = r.json()
                cid = cred.get("credential_id", "?")
                print(f"\n  🔑 SCENARIO 4: Credential issued for radiology-ai-reader")
                print(f"     Credential: {str(cid)[:8]}… | TTL: 1800s")

        print(f"\n{'='*60}")
        print("  ✅ Seeding Complete! Dashboard ready.")
        print(f"{'='*60}")
        print(f"\n  🌐 Dashboard:  {API_URL}/dashboard")
        print(f"  🤖 Agents:     {API_URL}/agents")
        print(f"  💓 Health:     {API_URL}/health")
        print(f"  📄 API Docs:   {API_URL}/docs\n")


if __name__ == "__main__":
    asyncio.run(seed_agents())
