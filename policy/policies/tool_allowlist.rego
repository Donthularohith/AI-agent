# Tool Allowlist Policy — MCP Tool URI Enforcement
#
# Validates that every MCP tool call is within the agent's declared allowlist.
# This is the first line of defense against tool abuse.
#
# Rohith: This is like a firewall rule — each agent has a "tool ACL" that
# defines exactly which MCP tools it can call. Anything not in the list is
# denied and logged.

package authz.tools

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default tool_allowed := false

# Tool is allowed if it's in the agent's allowlist
tool_allowed if {
    input.tool_uri in input.agent_record.allowed_tools
}

# Tool is allowed if no tool_uri was specified (non-tool actions)
tool_allowed if {
    not input.tool_uri
}

# ── Detailed Denial Info ────────────────────────────────────────────────
tool_denial_reason := sprintf(
    "Tool '%s' is not in the agent's allowed_tools list. Allowed tools: %v",
    [input.tool_uri, input.agent_record.allowed_tools]
) if {
    input.tool_uri
    not tool_allowed
}

# ── Tool Categories (for compliance reporting) ──────────────────────────
tool_category := "emr_read" if {
    startswith(input.tool_uri, "mcp://emr/") 
    contains(input.tool_uri, "/read")
}

tool_category := "emr_write" if {
    startswith(input.tool_uri, "mcp://emr/")
    contains(input.tool_uri, "/write")
}

tool_category := "data_export" if {
    contains(input.tool_uri, "/export")
}

tool_category := "admin" if {
    contains(input.tool_uri, "/admin")
}

tool_category := "general" if {
    not startswith(input.tool_uri, "mcp://emr/")
    not contains(input.tool_uri, "/export")
    not contains(input.tool_uri, "/admin")
}

# ── HIPAA-Sensitive Tool Check ──────────────────────────────────────────
hipaa_sensitive := true if {
    "HIPAA" in input.agent_record.compliance_tags
    startswith(input.tool_uri, "mcp://emr/")
}

hipaa_sensitive := false if {
    not "HIPAA" in input.agent_record.compliance_tags
}

hipaa_sensitive := false if {
    not startswith(input.tool_uri, "mcp://emr/")
}
