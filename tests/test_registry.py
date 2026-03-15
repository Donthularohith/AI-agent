"""Tests for Agent Registry — CRUD operations and API endpoints."""

import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone, timedelta


@pytest.mark.asyncio
async def test_register_agent_success(client, sample_agent_data):
    """Test successful agent registration via API."""
    response = await client.post("/agents", json=sample_agent_data)
    assert response.status_code == 201

    data = response.json()
    assert data["name"] == sample_agent_data["name"]
    assert data["owner_email"] == sample_agent_data["owner_email"].lower()
    assert data["status"] == "active"
    assert "agent_id" in data
    assert data["compliance_tags"] == ["HIPAA"]
    assert len(data["allowed_tools"]) == 2


@pytest.mark.asyncio
async def test_register_agent_duplicate_name(client, sample_agent_data):
    """Test that registering an agent with duplicate name fails."""
    # Register first
    response1 = await client.post("/agents", json=sample_agent_data)
    assert response1.status_code == 201

    # Try duplicate
    response2 = await client.post("/agents", json=sample_agent_data)
    assert response2.status_code == 400
    assert "already exists" in response2.json()["detail"]


@pytest.mark.asyncio
async def test_register_agent_invalid_tool_uri(client, sample_agent_data):
    """Test that invalid tool URIs are rejected."""
    sample_agent_data["allowed_tools"] = ["invalid://not-mcp"]
    response = await client.post("/agents", json=sample_agent_data)
    assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_get_agent(client, sample_agent_data):
    """Test retrieving an agent by ID."""
    # Register
    create_resp = await client.post("/agents", json=sample_agent_data)
    agent_id = create_resp.json()["agent_id"]

    # Get
    response = await client.get(f"/agents/{agent_id}")
    assert response.status_code == 200
    assert response.json()["agent_id"] == agent_id


@pytest.mark.asyncio
async def test_get_agent_not_found(client):
    """Test 404 for non-existent agent."""
    fake_id = str(uuid.uuid4())
    response = await client.get(f"/agents/{fake_id}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_suspend_agent(client, sample_agent_data):
    """Test agent suspension."""
    create_resp = await client.post("/agents", json=sample_agent_data)
    agent_id = create_resp.json()["agent_id"]

    response = await client.post(f"/agents/{agent_id}/suspend")
    assert response.status_code == 200
    assert response.json()["status"] == "suspended"


@pytest.mark.asyncio
async def test_revoke_agent(client, sample_agent_data):
    """Test permanent agent revocation."""
    create_resp = await client.post("/agents", json=sample_agent_data)
    agent_id = create_resp.json()["agent_id"]

    response = await client.post(f"/agents/{agent_id}/revoke")
    assert response.status_code == 200
    assert response.json()["status"] == "revoked"


@pytest.mark.asyncio
async def test_reactivate_suspended_agent(client, sample_agent_data):
    """Test reactivating a suspended agent."""
    create_resp = await client.post("/agents", json=sample_agent_data)
    agent_id = create_resp.json()["agent_id"]

    # Suspend
    await client.post(f"/agents/{agent_id}/suspend")

    # Reactivate
    response = await client.post(f"/agents/{agent_id}/reactivate")
    assert response.status_code == 200
    assert response.json()["status"] == "active"


@pytest.mark.asyncio
async def test_list_agents(client, sample_agent_data):
    """Test listing agents with pagination."""
    # Register an agent
    await client.post("/agents", json=sample_agent_data)

    response = await client.get("/agents")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] >= 1
    assert len(data["agents"]) >= 1
