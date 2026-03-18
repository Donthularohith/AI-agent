"""
API HTML Wrapper Middleware — Renders JSON responses as beautiful HTML when accessed from a browser.
Detects browser requests via Accept header and wraps JSON in a styled viewer.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, HTMLResponse
import json


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{title} — AI Agent Governance</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {{ --bg:#0a0e17; --bg2:#111827; --card:#1a2035; --border:#2a3450; --t1:#e2e8f0; --t2:#94a3b8; --t3:#64748b; --blue:#3b82f6; --cyan:#06b6d4; --green:#10b981; --amber:#f59e0b; --red:#ef4444; --purple:#8b5cf6; }}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:'Inter',system-ui,sans-serif; background:var(--bg); color:var(--t1); min-height:100vh; }}
body::before {{ content:''; position:fixed; inset:0; background-image:linear-gradient(rgba(59,130,246,.03)1px,transparent 1px),linear-gradient(90deg,rgba(59,130,246,.03)1px,transparent 1px); background-size:60px 60px; pointer-events:none; }}
.topbar {{ position:sticky; top:0; z-index:10; background:rgba(10,14,23,.92); backdrop-filter:blur(20px); border-bottom:1px solid var(--border); padding:0 28px; height:56px; display:flex; align-items:center; justify-content:space-between; }}
.topbar-left {{ display:flex; align-items:center; gap:14px; }}
.logo {{ width:32px; height:32px; background:linear-gradient(135deg,var(--blue),var(--cyan)); border-radius:8px; display:flex; align-items:center; justify-content:center; font-size:16px; box-shadow:0 0 16px rgba(59,130,246,.3); }}
.topbar h1 {{ font-size:15px; font-weight:600; }}
.topbar h1 span {{ background:linear-gradient(135deg,var(--blue),var(--cyan)); -webkit-background-clip:text; -webkit-text-fill-color:transparent; }}
.topbar-right {{ display:flex; gap:8px; }}
.topbar-right a {{ padding:6px 14px; border-radius:8px; font-size:12px; font-weight:600; text-decoration:none; border:1px solid var(--border); color:var(--t2); transition:all .2s; }}
.topbar-right a:hover {{ border-color:var(--blue); color:var(--t1); }}
.topbar-right a.active {{ background:linear-gradient(135deg,var(--blue),var(--cyan)); border:none; color:#fff; }}
.container {{ max-width:1200px; margin:0 auto; padding:24px 28px; position:relative; z-index:1; }}
.breadcrumb {{ font-size:13px; color:var(--t3); margin-bottom:16px; }}
.breadcrumb a {{ color:var(--blue); text-decoration:none; }}
.endpoint {{ display:inline-flex; align-items:center; gap:8px; padding:6px 14px; border-radius:8px; font-family:'JetBrains Mono',monospace; font-size:13px; margin-bottom:20px; }}
.endpoint.get {{ background:rgba(16,185,129,.1); color:var(--green); border:1px solid rgba(16,185,129,.25); }}
.endpoint.post {{ background:rgba(59,130,246,.1); color:var(--blue); border:1px solid rgba(59,130,246,.25); }}
.summary-row {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:20px; }}
.stat {{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:16px; }}
.stat-val {{ font-size:28px; font-weight:800; letter-spacing:-1px; }}
.stat-label {{ font-size:11px; color:var(--t3); text-transform:uppercase; letter-spacing:.5px; margin-top:2px; }}
.stat.healthy .stat-val {{ color:var(--green); }}
.stat.degraded .stat-val {{ color:var(--amber); }}
.stat.blue .stat-val {{ color:var(--blue); }}
.stat.green .stat-val {{ color:var(--green); }}
.stat.amber .stat-val {{ color:var(--amber); }}
.stat.red .stat-val {{ color:var(--red); }}
.stat.purple .stat-val {{ color:var(--purple); }}
.card {{ background:var(--card); border:1px solid var(--border); border-radius:14px; overflow:hidden; margin-bottom:20px; }}
.card-head {{ padding:14px 20px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }}
.card-head h2 {{ font-size:14px; font-weight:600; }}
table {{ width:100%; border-collapse:collapse; }}
th {{ text-align:left; padding:10px 18px; font-size:11px; font-weight:600; color:var(--t3); text-transform:uppercase; letter-spacing:.5px; background:rgba(0,0,0,.2); }}
td {{ padding:11px 18px; font-size:13px; border-bottom:1px solid rgba(42,52,80,.4); }}
tr:hover td {{ background:rgba(59,130,246,.03); }}
.badge {{ display:inline-flex; padding:3px 10px; border-radius:14px; font-size:11px; font-weight:600; }}
.badge.active {{ background:rgba(16,185,129,.12); color:var(--green); border:1px solid rgba(16,185,129,.25); }}
.badge.suspended {{ background:rgba(245,158,11,.12); color:var(--amber); border:1px solid rgba(245,158,11,.25); }}
.badge.revoked {{ background:rgba(239,68,68,.12); color:var(--red); border:1px solid rgba(239,68,68,.25); }}
.badge.connected {{ background:rgba(16,185,129,.12); color:var(--green); border:1px solid rgba(16,185,129,.25); }}
.badge.unreachable {{ background:rgba(239,68,68,.12); color:var(--red); border:1px solid rgba(239,68,68,.25); }}
.badge.hipaa {{ background:rgba(139,92,246,.12); color:var(--purple); border:1px solid rgba(139,92,246,.25); }}
.badge.pci {{ background:rgba(6,182,212,.12); color:var(--cyan); border:1px solid rgba(6,182,212,.25); }}
.mono {{ font-family:'JetBrains Mono',monospace; font-size:12px; }}
.json-toggle {{ background:var(--bg2); border:1px solid var(--border); color:var(--t2); padding:6px 14px; border-radius:8px; font-size:12px; cursor:pointer; font-family:inherit; }}
.json-toggle:hover {{ border-color:var(--blue); color:var(--t1); }}
.json-block {{ background:var(--bg2); border:1px solid var(--border); border-radius:10px; padding:16px; overflow-x:auto; display:none; }}
.json-block.show {{ display:block; }}
.json-block pre {{ font-family:'JetBrains Mono',monospace; font-size:12px; color:var(--t2); white-space:pre-wrap; word-break:break-word; }}
.footer {{ text-align:center; padding:28px; color:var(--t3); font-size:12px; border-top:1px solid var(--border); margin-top:40px; }}
.svc {{ display:flex; align-items:center; gap:10px; }}
.svc-dot {{ width:8px; height:8px; border-radius:50%; }}
.svc-dot.ok {{ background:var(--green); box-shadow:0 0 8px rgba(16,185,129,.4); }}
.svc-dot.fail {{ background:var(--red); box-shadow:0 0 8px rgba(239,68,68,.4); }}
</style>
</head>
<body>
<div class="topbar">
  <div class="topbar-left"><div class="logo">🛡️</div><h1><span>AI Agent Governance</span> — {title}</h1></div>
  <div class="topbar-right">
    <a href="/dashboard" class="active">📊 Dashboard</a>
    <a href="/agents">🤖 Agents</a>
    <a href="/health">💓 Health</a>
    <a href="/docs">📄 API Docs</a>
  </div>
</div>
<div class="container">
  <div class="breadcrumb"><a href="/dashboard">Dashboard</a> / {breadcrumb}</div>
  <div class="endpoint get">GET {path}</div>
  {content}
  <div class="card" style="margin-top:20px">
    <div class="card-head"><h2>📦 Raw JSON Response</h2><button class="json-toggle" onclick="document.getElementById('raw').classList.toggle('show')">Toggle JSON</button></div>
    <div id="raw" class="json-block"><pre>{raw_json}</pre></div>
  </div>
</div>
<footer class="footer">AI Agent Identity Governance Platform v1.0.0 — Built by <strong>Rohith Donthula</strong></footer>
</body></html>"""


def render_health_html(data: dict, path: str) -> str:
    status = data.get("status", "unknown")
    services = {k: v for k, v in data.items() if k not in ("status", "timestamp")}
    
    summary = f'<div class="summary-row">'
    summary += f'<div class="stat {"healthy" if status=="healthy" else "degraded"}"><div class="stat-val">{"✅" if status=="healthy" else "⚠️"} {status.upper()}</div><div class="stat-label">Platform Status</div></div>'
    for svc, state in services.items():
        ok = state == "connected"
        summary += f'<div class="stat {"green" if ok else "red"}"><div class="stat-val"><div class="svc"><div class="svc-dot {"ok" if ok else "fail"}"></div>{state}</div></div><div class="stat-label">{svc}</div></div>'
    summary += '</div>'
    
    return HTML_TEMPLATE.format(title="Health Check", breadcrumb="Health", path=path, content=summary, raw_json=json.dumps(data, indent=2, default=str))


def render_agents_html(data: dict, path: str) -> str:
    agents = data.get("agents", [])
    total = data.get("total", len(agents))
    active = sum(1 for a in agents if a.get("status") == "active")
    suspended = sum(1 for a in agents if a.get("status") == "suspended")
    hipaa = sum(1 for a in agents if "HIPAA" in (a.get("compliance_tags") or []))
    
    summary = f'''<div class="summary-row">
      <div class="stat blue"><div class="stat-val">{total}</div><div class="stat-label">Total Agents</div></div>
      <div class="stat green"><div class="stat-val">{active}</div><div class="stat-label">Active</div></div>
      <div class="stat amber"><div class="stat-val">{suspended}</div><div class="stat-label">Suspended</div></div>
      <div class="stat purple"><div class="stat-val">{hipaa}</div><div class="stat-label">HIPAA Tagged</div></div>
    </div>'''
    
    if agents:
        rows = ""
        for a in agents:
            tags = " ".join(f'<span class="badge {t.lower()}">{t}</span>' for t in (a.get("compliance_tags") or []))
            tools_count = len(a.get("allowed_tools") or [])
            sid = a.get("agent_id", "")[:8]
            rows += f'''<tr>
              <td><strong>{a.get("name","")}</strong><div class="mono" style="color:var(--t3);margin-top:2px">{sid}…</div></td>
              <td><span class="badge {a.get("status","")}">{a.get("status","").upper()}</span></td>
              <td style="font-size:12px">{a.get("owner_email","")}</td>
              <td class="mono">{a.get("version","")}</td>
              <td>{tags or "—"}</td>
              <td class="mono">{tools_count} tools</td>
            </tr>'''
        summary += f'''<div class="card"><div class="card-head"><h2>🤖 Agent Registry ({total})</h2></div>
          <table><thead><tr><th>Agent</th><th>Status</th><th>Owner</th><th>Version</th><th>Compliance</th><th>Tools</th></tr></thead>
          <tbody>{rows}</tbody></table></div>'''
    else:
        summary += '<div class="card"><div style="padding:40px;text-align:center;color:var(--t3)">No agents registered yet.</div></div>'
    
    return HTML_TEMPLATE.format(title="Agent Registry", breadcrumb="Agents", path=path, content=summary, raw_json=json.dumps(data, indent=2, default=str))


def render_generic_html(data, path: str) -> str:
    title = path.strip("/").replace("/", " / ").title() or "API"
    content = ""
    if isinstance(data, dict):
        items = "".join(f'<tr><td class="mono" style="color:var(--blue)">{k}</td><td>{render_value(v)}</td></tr>' for k, v in data.items())
        content = f'<div class="card"><div class="card-head"><h2>📋 Response Data</h2></div><table><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>{items}</tbody></table></div>'
    elif isinstance(data, list):
        content = f'<div class="card"><div class="card-head"><h2>📋 {len(data)} Items</h2></div><table><tbody>'
        for i, item in enumerate(data[:50]):
            content += f'<tr><td class="mono" style="color:var(--t3)">#{i+1}</td><td>{render_value(item)}</td></tr>'
        content += '</tbody></table></div>'
    
    return HTML_TEMPLATE.format(title=title, breadcrumb=title, path=path, content=content, raw_json=json.dumps(data, indent=2, default=str))


def render_value(v):
    if isinstance(v, bool):
        return f'<span class="badge {"connected" if v else "unreachable"}">{"true" if v else "false"}</span>'
    if isinstance(v, (int, float)):
        return f'<span class="mono">{v}</span>'
    if isinstance(v, str):
        if len(v) > 80:
            return f'<span style="font-size:12px">{v[:80]}…</span>'
        return v
    if isinstance(v, list):
        if not v:
            return '<span style="color:var(--t3)">[]</span>'
        return ", ".join(f'<span class="badge hipaa">{x}</span>' if isinstance(x, str) else str(x) for x in v[:5])
    if isinstance(v, dict):
        return f'<span class="mono" style="color:var(--t3)">{json.dumps(v)[:100]}</span>'
    return str(v)


class HTMLWrapperMiddleware(BaseHTTPMiddleware):
    """Wraps JSON API responses in beautiful HTML when accessed from a browser."""
    
    SKIP_PATHS = {"/docs", "/redoc", "/openapi.json", "/dashboard", "/favicon.ico"}
    SKIP_PREFIXES = ("/static/", "/docs/")
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # Skip non-browser or excluded paths
        if any(path.startswith(p) for p in self.SKIP_PREFIXES):
            return await call_next(request)
        if path in self.SKIP_PATHS:
            return await call_next(request)
        
        accept = request.headers.get("accept", "")
        if "text/html" not in accept:
            return await call_next(request)
        
        try:
            response = await call_next(request)
        except Exception as e:
            error_html = HTML_TEMPLATE.format(
                title="Server Error", breadcrumb="Error", path=path,
                content=f'<div class="stat red"><div class="stat-val">500 Error</div><div class="stat-label">{str(e)[:200]}</div></div>',
                raw_json=json.dumps({"error": str(e)}, indent=2)
            )
            return HTMLResponse(content=error_html, status_code=500)
        
        # Only wrap JSON responses
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            return response
        
        # Read the response body
        try:
            body = b""
            async for chunk in response.body_iterator:
                body += chunk
        except Exception:
            return response
        
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, Exception):
            return Response(content=body, status_code=response.status_code, 
                          headers=dict(response.headers), media_type=content_type)
        
        # If it's an error response, show error page
        if response.status_code >= 400:
            error_detail = data.get("detail", str(data)) if isinstance(data, dict) else str(data)
            error_html = HTML_TEMPLATE.format(
                title=f"Error {response.status_code}", breadcrumb="Error", path=path,
                content=f'<div class="summary-row"><div class="stat red"><div class="stat-val">{response.status_code}</div><div class="stat-label">Error</div></div></div><div class="card"><div style="padding:20px;color:var(--t2)">{error_detail[:500]}</div></div>',
                raw_json=json.dumps(data, indent=2, default=str)
            )
            return HTMLResponse(content=error_html, status_code=response.status_code)
        
        # Choose renderer based on path
        try:
            if path == "/health" or path.startswith("/health"):
                html = render_health_html(data, path)
            elif path == "/agents" or path == "/agents/":
                html = render_agents_html(data, path)
            else:
                html = render_generic_html(data, path)
        except Exception as e:
            # Fallback: show raw JSON in styled page
            html = render_generic_html(data, path)
        
        return HTMLResponse(content=html, status_code=response.status_code)
