# Agent Authorization Policy — Main OPA Rego Policy
#
# Evaluates every agent action against five checks:
# 1. Agent status must be "active"
# 2. Session token must not be expired
# 3. Requested tool URI must be in agent's allowed_tools list
# 4. Requested resource must match an allowed resource pattern
# 5. Delegation depth must be within max_delegation_depth limit
#
# Rohith: Think of this as a Splunk correlation search that fires on every
# agent action — it evaluates context and produces an allow/deny decision
# with full audit trail context.

package authz

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# Default deny — fail closed
default allow := false
default reason := "denied_by_default"
default audit_required := true

# Main allow rule — all checks must pass
allow if {
    agent_is_active
    token_not_expired
    tool_in_allowlist
    resource_pattern_matched
    delegation_depth_valid
}

reason := "all_checks_passed" if {
    allow
}

# ── Check 1: Agent Status ───────────────────────────────────────────────
agent_is_active if {
    input.agent_record.status == "active"
}

reason := "agent_not_active" if {
    not agent_is_active
}

# ── Check 2: Token Expiry ───────────────────────────────────────────────
token_not_expired if {
    not input.session_token_claims.expires_at
}

token_not_expired if {
    input.session_token_claims.expires_at
    time.parse_rfc3339_ns(input.session_token_claims.expires_at) > time.now_ns()
}

reason := "token_expired" if {
    agent_is_active
    not token_not_expired
}

# ── Check 3: Tool Allowlist ─────────────────────────────────────────────
tool_in_allowlist if {
    not input.tool_uri
}

tool_in_allowlist if {
    input.tool_uri
    input.tool_uri in input.agent_record.allowed_tools
}

reason := "tool_not_in_allowlist" if {
    agent_is_active
    token_not_expired
    not tool_in_allowlist
}

# ── Check 4: Resource Pattern Match ─────────────────────────────────────
resource_pattern_matched if {
    not input.resource
}

resource_pattern_matched if {
    input.resource
    some pattern in input.agent_record.allowed_resources
    resource_matches(input.resource, pattern)
}

resource_matches(resource, pattern) if {
    pattern == "*"
}

resource_matches(resource, pattern) if {
    endswith(pattern, ":*")
    prefix := trim_suffix(pattern, "*")
    startswith(resource, prefix)
}

resource_matches(resource, pattern) if {
    not endswith(pattern, ":*")
    pattern != "*"
    resource == pattern
}

reason := "resource_not_allowed" if {
    agent_is_active
    token_not_expired
    tool_in_allowlist
    not resource_pattern_matched
}

# ── Check 5: Delegation Depth ───────────────────────────────────────────
delegation_depth_valid if {
    input.delegation_depth <= input.agent_record.max_delegation_depth
}

reason := "delegation_depth_exceeded" if {
    agent_is_active
    token_not_expired
    tool_in_allowlist
    resource_pattern_matched
    not delegation_depth_valid
}

# ── Denied Reasons (aggregated) ─────────────────────────────────────────
denied_reasons contains "Agent status is not active" if {
    not agent_is_active
}

denied_reasons contains "Session token has expired" if {
    not token_not_expired
}

denied_reasons contains sprintf("Tool '%s' not in allowed_tools list", [input.tool_uri]) if {
    input.tool_uri
    not tool_in_allowlist
}

denied_reasons contains "Resource does not match any allowed pattern" if {
    input.resource
    not resource_pattern_matched
}

denied_reasons contains sprintf("Delegation depth %d exceeds maximum %d", [input.delegation_depth, input.agent_record.max_delegation_depth]) if {
    not delegation_depth_valid
}

# ── Compliance Flags ────────────────────────────────────────────────────
compliance_flags := input.agent_record.compliance_tags if {
    input.agent_record.compliance_tags
}

compliance_flags := [] if {
    not input.agent_record.compliance_tags
}
