"""
Seed Demo Agents — Populate the registry with realistic healthcare agents.

Creates 4 demo agents matching the healthcare use cases from the PRD:
1. emr-patient-reader — reads patient demographics and labs
2. claims-processor — processes insurance claims
3. clinical-summarizer — generates clinical summaries
4. prescription-validator — validates prescriptions

Run: python -m scripts.seed_demo_agents
"""

import asyncio
import httpx
from datetime import datetime, timezone, timedelta

API_URL = "http://localhost:8080"

DEMO_AGENTS = [
    {
        "name": "emr-patient-reader",
        "version": "1.0.0",
        "owner_email": "rohith.donthula@cerner.com",
        "purpose": "Read patient demographics and lab results from EMR for clinical decision support workflows",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=90)).isoformat(),
        "allowed_tools": [
            "mcp://emr/patient/read",
            "mcp://emr/labs/query",
            "mcp://emr/demographics/search",
        ],
        "allowed_resources": [
            "emr:patients:demographics:*",
            "emr:patients:labs:*",
        ],
        "max_delegation_depth": 1,
        "credential_ttl_seconds": 900,
        "anomaly_threshold": -0.3,
        "compliance_tags": ["HIPAA"],
    },
    {
        "name": "claims-processor",
        "version": "2.1.0",
        "owner_email": "sarah.johnson@cerner.com",
        "purpose": "Automated processing and validation of insurance claims with ICD-10 code verification",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=180)).isoformat(),
        "allowed_tools": [
            "mcp://billing/claims/submit",
            "mcp://billing/claims/validate",
            "mcp://billing/icd10/lookup",
        ],
        "allowed_resources": [
            "billing:claims:*",
            "billing:icd10:codes:*",
        ],
        "max_delegation_depth": 0,
        "credential_ttl_seconds": 600,
        "anomaly_threshold": -0.25,
        "compliance_tags": ["HIPAA", "PCI"],
    },
    {
        "name": "clinical-summarizer",
        "version": "1.3.0",
        "owner_email": "rohith.donthula@cerner.com",
        "purpose": "Generate clinical summaries from patient records using LLM for physician review",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=60)).isoformat(),
        "allowed_tools": [
            "mcp://emr/patient/read",
            "mcp://emr/notes/read",
            "mcp://llm/summarize",
        ],
        "allowed_resources": [
            "emr:patients:demographics:*",
            "emr:patients:notes:*",
            "emr:patients:labs:*",
        ],
        "max_delegation_depth": 2,
        "credential_ttl_seconds": 1200,
        "anomaly_threshold": -0.3,
        "compliance_tags": ["HIPAA"],
    },
    {
        "name": "prescription-validator",
        "version": "1.0.0",
        "owner_email": "mike.chen@cerner.com",
        "purpose": "Validate prescription orders against drug interaction databases and formulary",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "allowed_tools": [
            "mcp://pharmacy/drugs/lookup",
            "mcp://pharmacy/interactions/check",
            "mcp://pharmacy/formulary/verify",
        ],
        "allowed_resources": [
            "pharmacy:drugs:*",
            "pharmacy:interactions:*",
            "pharmacy:formulary:*",
        ],
        "max_delegation_depth": 0,
        "credential_ttl_seconds": 300,
        "anomaly_threshold": -0.35,
        "compliance_tags": ["HIPAA"],
    },
]


async def seed_agents():
    """Register all demo agents."""
    async with httpx.AsyncClient(base_url=API_URL, timeout=10) as client:
        print(f"\n{'='*60}")
        print("  Seeding Demo Agents")
        print(f"{'='*60}")

        for agent_data in DEMO_AGENTS:
            try:
                response = await client.post("/agents", json=agent_data)
                if response.status_code == 201:
                    result = response.json()
                    print(f"  ✅ {agent_data['name']}")
                    print(f"     ID: {result['agent_id']}")
                    print(f"     Owner: {agent_data['owner_email']}")
                    print(f"     Tags: {agent_data['compliance_tags']}")
                elif response.status_code == 400 and "already exists" in response.text:
                    print(f"  ⏩ {agent_data['name']} (already exists)")
                else:
                    print(f"  ❌ {agent_data['name']}: {response.status_code} - {response.text}")
            except Exception as e:
                print(f"  ❌ {agent_data['name']}: {str(e)}")

        print(f"\n{'='*60}")
        print("  Verifying agent fleet...")
        response = await client.get("/agents")
        if response.status_code == 200:
            data = response.json()
            print(f"  Total agents: {data['total']}")
        print(f"{'='*60}\n")


if __name__ == "__main__":
    asyncio.run(seed_agents())
