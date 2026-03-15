"""
Attack Simulation Script — Demonstrate Governance Platform Defenses

Simulates 3 attack scenarios to demonstrate the platform's detection and
enforcement capabilities:

Scenario 1: Tool Allowlist Violation
  Agent tries to call a tool not in its allowlist (mcp://emr/admin/delete)

Scenario 2: Delegation Chain Explosion
  Child agent tries to register with broader scope than parent

Scenario 3: Anomalous Behavior (Rapid Fire + Out of Hours)
  Agent sends rapid tool calls to trigger circuit breaker

Run: python -m scripts.simulate_attack
"""

import asyncio
import uuid
import httpx
from datetime import datetime, timezone, timedelta

API_URL = "http://localhost:8000"


async def scenario_1_tool_violation():
    """
    Scenario 1: Unauthorized Tool Access

    MITRE ATT&CK: T1210 (Exploitation of Remote Services)

    The emr-patient-reader agent tries to call an admin delete tool
    that's not in its allowlist. The OPA policy should deny this.
    """
    print("\n" + "=" * 60)
    print("  SCENARIO 1: Tool Allowlist Violation")
    print("  MITRE ATT&CK: T1210 (Exploitation of Remote Services)")
    print("=" * 60)

    async with httpx.AsyncClient(base_url=API_URL, timeout=10) as client:
        # Find the emr-patient-reader agent
        resp = await client.get("/agents")
        agents = resp.json().get("agents", [])
        reader = next((a for a in agents if a["name"] == "emr-patient-reader"), None)

        if not reader:
            print("  ❌ emr-patient-reader not found. Run seed_demo_agents first.")
            return

        agent_id = reader["agent_id"]
        print(f"  Target agent: emr-patient-reader ({agent_id[:8]}...)")
        print(f"  Allowed tools: {reader['allowed_tools']}")
        print(f"  Attempting unauthorized tool: mcp://emr/admin/delete")

        # Try to call unauthorized tool via policy decision endpoint
        policy_request = {
            "agent_id": agent_id,
            "action": "tool_call",
            "resource": "emr:admin:all",
            "tool_uri": "mcp://emr/admin/delete",
            "delegation_depth": 0,
        }

        resp = await client.post("/policy/decide", json=policy_request)
        decision = resp.json()

        if not decision.get("allow"):
            print(f"\n  ✅ ATTACK BLOCKED!")
            print(f"     Reason: {decision.get('reason')}")
            print(f"     Denied: {decision.get('denied_reasons')}")
        else:
            print(f"\n  ⚠️  Attack was not blocked — check OPA configuration")

        # Also try a legitimate tool call
        print(f"\n  Verifying legitimate tool call still works...")
        legit_request = {
            "agent_id": agent_id,
            "action": "tool_call",
            "resource": "emr:patients:demographics:12345",
            "tool_uri": "mcp://emr/patient/read",
            "delegation_depth": 0,
        }
        resp = await client.post("/policy/decide", json=legit_request)
        decision = resp.json()
        if decision.get("allow"):
            print(f"  ✅ Legitimate tool call ALLOWED (correct)")
        else:
            print(f"  ℹ️  Decision: {decision}")


async def scenario_2_delegation_escalation():
    """
    Scenario 2: Delegation Scope Escalation

    MITRE ATT&CK: T1078 (Valid Accounts) + T1134 (Access Token Manipulation)

    A child agent tries to register with broader scope than its parent,
    attempting to escalate privileges through the delegation chain.
    """
    print("\n" + "=" * 60)
    print("  SCENARIO 2: Delegation Chain Privilege Escalation")
    print("  MITRE ATT&CK: T1078 + T1134")
    print("=" * 60)

    async with httpx.AsyncClient(base_url=API_URL, timeout=10) as client:
        # Find parent agent
        resp = await client.get("/agents")
        agents = resp.json().get("agents", [])
        parent = next((a for a in agents if a["name"] == "emr-patient-reader"), None)

        if not parent:
            print("  ❌ emr-patient-reader not found. Run seed_demo_agents first.")
            return

        print(f"  Parent agent: emr-patient-reader")
        print(f"  Parent tools: {parent['allowed_tools']}")
        print(f"  Parent resources: {parent['allowed_resources']}")
        print(f"  Parent max_delegation_depth: {parent['max_delegation_depth']}")

        # Try to create child with broader scope (should be denied)
        print(f"\n  Attempting privilege escalation via delegation...")
        malicious_child = {
            "name": "evil-child-agent",
            "version": "1.0.0",
            "owner_email": "attacker@evil.com",
            "purpose": "Malicious child agent attempting to escalate privileges via delegation chain",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            "allowed_tools": [
                "mcp://emr/patient/read",
                "mcp://emr/admin/delete",  # NOT in parent's allowlist
                "mcp://emr/billing/export",  # NOT in parent's allowlist
            ],
            "allowed_resources": [
                "emr:*",  # Broader than parent's scope
            ],
            "max_delegation_depth": 5,  # Exceeds parent's depth
            "parent_agent_id": parent["agent_id"],
            "credential_ttl_seconds": 86400,  # Much longer than parent
            "compliance_tags": [],
        }

        resp = await client.post("/agents", json=malicious_child)
        if resp.status_code == 400:
            error = resp.json()
            print(f"\n  ✅ ESCALATION BLOCKED!")
            print(f"     Reason: {error.get('detail', 'Unknown')[:200]}")
        else:
            print(f"\n  ⚠️  Status {resp.status_code}: {resp.text[:200]}")


async def scenario_3_rapid_fire_circuit_breaker():
    """
    Scenario 3: Rapid-Fire Tool Calls (Circuit Breaker Trigger)

    MITRE ATT&CK: T1498 (Network Denial of Service) + T1499 (Endpoint DoS)

    An agent rapidly sends policy requests that get denied, triggering
    the circuit breaker that auto-suspends the agent.
    """
    print("\n" + "=" * 60)
    print("  SCENARIO 3: Rapid-Fire Attack (Circuit Breaker)")
    print("  MITRE ATT&CK: T1498 + T1499")
    print("=" * 60)

    async with httpx.AsyncClient(base_url=API_URL, timeout=10) as client:
        resp = await client.get("/agents")
        agents = resp.json().get("agents", [])
        target = next((a for a in agents if a["name"] == "claims-processor"), None)

        if not target:
            print("  ❌ claims-processor not found. Run seed_demo_agents first.")
            return

        print(f"  Target agent: claims-processor ({target['agent_id'][:8]}...)")
        print(f"  Simulating rapid unauthorized tool calls...")

        denied_count = 0
        for i in range(8):
            request = {
                "agent_id": target["agent_id"],
                "action": "tool_call",
                "resource": f"emr:admin:secrets:{i}",
                "tool_uri": "mcp://emr/admin/export-all",  # Not in allowlist
                "delegation_depth": 0,
            }

            resp = await client.post("/policy/decide", json=request)
            decision = resp.json()

            if not decision.get("allow"):
                denied_count += 1
                print(f"  Request {i+1}: DENIED ({decision.get('reason')})")
            else:
                print(f"  Request {i+1}: allowed")

            await asyncio.sleep(0.1)  # Rapid but not instant

        print(f"\n  Results: {denied_count}/8 requests denied")
        if denied_count >= 5:
            print(f"  ✅ Circuit breaker should have tripped — "
                  f"agent would be auto-suspended in production")
        print(f"  In a full setup, the SOC dashboard would show this agent "
              f"with a CRITICAL alert.")


async def run_all_scenarios():
    """Run all attack simulation scenarios."""
    print("\n" + "=" * 60)
    print("  AI AGENT GOVERNANCE — ATTACK SIMULATION")
    print("  Demonstrating detection and enforcement capabilities")
    print("=" * 60)

    # Check API connectivity
    try:
        async with httpx.AsyncClient(base_url=API_URL, timeout=5) as client:
            resp = await client.get("/health")
            health = resp.json()
            print(f"\n  Platform Status: {health.get('status', 'unknown')}")
            print(f"  Database: {health.get('database', 'unknown')}")
    except Exception as e:
        print(f"\n  ❌ Cannot connect to API at {API_URL}: {e}")
        print(f"     Start the API first: uvicorn api.main:app --reload")
        return

    await scenario_1_tool_violation()
    await scenario_2_delegation_escalation()
    await scenario_3_rapid_fire_circuit_breaker()

    print("\n" + "=" * 60)
    print("  SIMULATION COMPLETE")
    print("  Check the SOC dashboard at http://localhost:8501 for alerts")
    print("  Check audit logs via GET /audit/agents/{agent_id}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(run_all_scenarios())
