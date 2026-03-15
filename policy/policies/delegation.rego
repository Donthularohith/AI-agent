# Delegation Chain Policy — Depth Limit Enforcement
#
# Enforces that child agents cannot exceed their parent's delegation depth
# and cannot acquire broader scope than their parent.
#
# MITRE ATT&CK relevance: Prevents T1078 (Valid Accounts) escalation via
# delegation chain exploitation.

package authz.delegation

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default delegation_allowed := false

# Allow delegation if all delegation-specific checks pass
delegation_allowed if {
    parent_exists
    depth_within_limit
    scope_is_subset
    parent_is_active
}

# ── Check: Parent Agent Exists ──────────────────────────────────────────
parent_exists if {
    input.parent_agent_id
    input.parent_agent_record
}

parent_exists if {
    not input.parent_agent_id
}

# ── Check: Delegation Depth Within Limit ────────────────────────────────
depth_within_limit if {
    input.requested_delegation_depth <= input.parent_agent_record.max_delegation_depth
}

depth_within_limit if {
    not input.parent_agent_id
    input.requested_delegation_depth <= input.max_delegation_depth_limit
}

# ── Check: Child Scope is Subset of Parent ──────────────────────────────
scope_is_subset if {
    not input.parent_agent_id
}

scope_is_subset if {
    input.parent_agent_id
    tools_are_subset
    resources_are_subset
}

tools_are_subset if {
    every tool in input.requested_tools {
        tool in input.parent_agent_record.allowed_tools
    }
}

resources_are_subset if {
    every resource in input.requested_resources {
        some parent_resource in input.parent_agent_record.allowed_resources
        resource_within_scope(resource, parent_resource)
    }
}

resource_within_scope(child_resource, parent_resource) if {
    parent_resource == "*"
}

resource_within_scope(child_resource, parent_resource) if {
    endswith(parent_resource, ":*")
    prefix := trim_suffix(parent_resource, "*")
    startswith(child_resource, prefix)
}

resource_within_scope(child_resource, parent_resource) if {
    child_resource == parent_resource
}

# ── Check: Parent Must Be Active ────────────────────────────────────────
parent_is_active if {
    not input.parent_agent_id
}

parent_is_active if {
    input.parent_agent_record.status == "active"
}

# ── Denial Reasons ──────────────────────────────────────────────────────
delegation_denied_reasons contains "Parent agent does not exist" if {
    input.parent_agent_id
    not input.parent_agent_record
}

delegation_denied_reasons contains "Parent agent is not active" if {
    input.parent_agent_record
    not parent_is_active
}

delegation_denied_reasons contains sprintf("Requested delegation depth %d exceeds parent max %d", [input.requested_delegation_depth, input.parent_agent_record.max_delegation_depth]) if {
    input.parent_agent_id
    not depth_within_limit
}

delegation_denied_reasons contains "Requested tools are not a subset of parent tools" if {
    input.parent_agent_id
    not tools_are_subset
}

delegation_denied_reasons contains "Requested resources exceed parent resource scope" if {
    input.parent_agent_id
    not resources_are_subset
}
