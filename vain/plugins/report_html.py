"""Report plugin: a self-contained HTML report (open in a browser, or Print -> Save as PDF).

Adds:  --output FILE.html
The page has no external resources (no fonts, scripts or CDNs), so it works
offline and can be emailed as one file. All scan-derived text is HTML-escaped.
"""

from __future__ import annotations

import re
from pathlib import Path

from jinja2 import Environment
from markupsafe import Markup, escape

from vain.errors import PluginConfigError
from vain.models import utcnow
from vain.plugin import Plugin

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_CODE = re.compile(r"(?<!\w)'([^'\n]{1,300})'(?!\w)|`([^`\n]{1,300})`")


def fix_format(text: str) -> Markup:
    """Escape text, rendering 'quoted' or `backticked` fragments as <code>."""
    parts, pos = [], 0
    for m in _CODE.finditer(text or ""):
        parts.append(escape(text[pos : m.start()]))
        parts.append(Markup("<code>") + escape(m.group(1) or m.group(2)) + Markup("</code>"))
        pos = m.end()
    parts.append(escape((text or "")[pos:]))
    return Markup("").join(parts)


TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vain report {{ scan.scan_id }}</title>
<style>
:root{--bg:#f5f6f8;--panel:#fff;--ink:#14171c;--muted:#5b6471;--line:#e2e5ea;--code:#eef0f4;--accent:#4338ca;
--critical:#b42318;--high:#c4510a;--medium:#9a6b00;--low:#0b6e80;--info:#667085}
@media (prefers-color-scheme:dark){:root{--bg:#0d1015;--panel:#151a21;--ink:#e7eaef;--muted:#8d97a5;--line:#252c36;--code:#0a0d11;--accent:#9a9cff;
--critical:#ff7a70;--high:#ff9a52;--medium:#f2bd45;--low:#55c6db;--info:#8d97a5}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:40px 24px 64px}
header{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap;margin-bottom:28px}
h1{font-size:30px;letter-spacing:-.02em;margin:0}
h1 span{color:var(--accent)}
.meta{color:var(--muted);font-size:13px;text-align:right}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted);margin:36px 0 12px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}
.card b{display:block;font-size:28px;line-height:1.1;letter-spacing:-.02em}
.card small{color:var(--muted)}
.card.sev b{color:var(--c)}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;vertical-align:top;padding:12px 14px;border-bottom:1px solid var(--line)}
th{font-size:12px;color:var(--muted);font-weight:600;background:color-mix(in srgb,var(--panel) 92%,var(--ink))}
tr:last-child td{border-bottom:0}
.pill{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11px;font-weight:700;letter-spacing:.04em;color:#fff;background:var(--c)}
.CRITICAL{--c:var(--critical)}.HIGH{--c:var(--high)}.MEDIUM{--c:var(--medium)}.LOW{--c:var(--low)}.INFO{--c:var(--info)}
.sub{color:var(--muted);font-size:13px;margin-top:3px}
.tag{display:inline-block;font-size:11px;padding:1px 7px;border-radius:6px;border:1px solid var(--line);color:var(--muted);margin-right:4px}
td code.where{white-space:nowrap}
code{font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--code);padding:2px 6px;border-radius:5px;word-break:break-word}
.empty{padding:22px;color:var(--muted)}
.diff li{margin:2px 0}
.warn{border-left:3px solid var(--medium);padding:8px 14px;margin:6px 0;background:var(--panel);border-radius:0 8px 8px 0}
footer{margin-top:44px;color:var(--muted);font-size:12px}
@media print{body{background:#fff}.panel,.card{break-inside:avoid;border-color:#ccc}.wrap{padding:0}}
</style>
</head>
<body><div class="wrap">
<header>
  <h1><span>Vain</span> security report</h1>
  <div class="meta">Scan {{ scan.scan_id }}<br>{{ generated }}<br>{{ scan.nmap_version and ("Nmap " ~ scan.nmap_version) or "" }}</div>
</header>

<h2>Summary</h2>
<div class="cards">
  <div class="card"><b>{{ hosts|length }}</b><small>hosts up</small></div>
  <div class="card"><b>{{ open_ports }}</b><small>open ports</small></div>
  <div class="card"><b>{{ findings|length }}</b><small>findings</small></div>
  {% for s in severities %}{% if counts[s] %}<div class="card sev {{ s }}"><b>{{ counts[s] }}</b><small>{{ s|lower }}</small></div>{% endif %}{% endfor %}
</div>

{% if diff %}
<h2>Changes since the previous scan</h2>
<div class="panel"><div class="empty diff">
{% if diff.baseline %}No previous scan existed, so this run is the new baseline.
{% else %}<ul>
{% for k, label in [("new_hosts","New host"),("gone_hosts","Host no longer seen"),("new_ports","Newly open port"),("closed_ports","Port now closed")] %}{% for item in diff[k] %}<li><b>{{ label }}:</b> {{ item }}</li>{% endfor %}{% endfor %}
{% for item in diff.new_findings %}<li><b>New finding:</b> <span class="pill {{ item.severity }}">{{ item.severity }}</span> {{ item.host }} - {{ item.title }}</li>{% endfor %}
{% for item in diff.resolved_findings %}<li><b>Resolved:</b> {{ item.host }} - {{ item.title }}</li>{% endfor %}
</ul>{% if not (diff.new_hosts or diff.gone_hosts or diff.new_ports or diff.closed_ports or diff.new_findings or diff.resolved_findings) %}No changes.{% endif %}
{% endif %}
</div></div>
{% endif %}

<h2>Findings</h2>
<div class="panel">
{% if findings %}
<table>
<tr><th>Severity</th><th>Where</th><th>Finding</th><th>How to fix</th></tr>
{% for f in findings %}
<tr>
  <td><span class="pill {{ f.severity.value }}">{{ f.severity.value }}</span>
      <div class="sub">score {{ "%.0f"|format(f.risk_score) }}{% if f.base_severity != f.severity %}<br>was {{ f.base_severity.value|lower }}{% endif %}</div></td>
  <td><code class="where">{{ f.target }}</code>{% if f.asset %}<div class="sub">{{ f.asset }} ({{ f.criticality|lower }})</div>{% endif %}</td>
  <td><b>{{ f.title }}</b>
      <div class="sub">
        <span class="tag">{{ f.source }}</span>
        {% if f.cvss is not none %}<span class="tag">CVSS {{ "%.1f"|format(f.cvss) }}</span>{% endif %}
        {% if f.epss is not none %}<span class="tag">EPSS {{ "%.1f"|format(f.epss*100) }}%</span>{% endif %}
        {% if f.cve %}<span class="tag">{{ f.cve }}</span>{% endif %}
      </div>
      {% if f.description %}<div class="sub">{{ f.description }}</div>{% endif %}
      {% if f.evidence %}<div class="sub"><code>{{ f.evidence[:300] }}</code></div>{% endif %}</td>
  <td>{{ f.remediation|fixfmt if f.remediation else "-" }}</td>
</tr>
{% endfor %}
</table>
{% else %}<div class="empty">No findings. Nothing in this scan violated the active checks.</div>{% endif %}
</div>

<h2>Hosts and services</h2>
<div class="panel">
{% if hosts %}
<table>
<tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th></tr>
{% for h in hosts %}{% for s in h.open_services %}
<tr><td>{% if loop.first %}<b>{{ h.address }}</b>{% if h.hostname %}<div class="sub">{{ h.hostname }}</div>{% endif %}{% if h.os_guess %}<div class="sub">{{ h.os_guess }}</div>{% endif %}{% endif %}</td>
<td><code>{{ s.port }}/{{ s.protocol }}</code></td><td>{{ s.name }}</td><td>{{ s.banner }}</td></tr>
{% else %}<tr><td><b>{{ h.address }}</b></td><td colspan="3" class="sub">no open ports found</td></tr>{% endfor %}{% endfor %}
</table>
{% else %}<div class="empty">No hosts were up.</div>{% endif %}
</div>

{% if warnings %}<h2>Notices</h2>{% for w in warnings %}<div class="warn">{{ w }}</div>{% endfor %}{% endif %}

<footer>Generated by Vain for authorized network auditing only. Version banners can be inaccurate (distributions back-port fixes); verify before acting.</footer>
</div></body></html>
"""

_env = Environment(autoescape=True)  # autoescape ON: scan data is untrusted
_env.filters["fixfmt"] = fix_format
_template = _env.from_string(TEMPLATE)


def render(ctx) -> str:
    counts = {s: 0 for s in SEVERITIES}
    for f in ctx.findings:
        counts[f.severity.value] += 1
    return _template.render(
        scan=ctx.result,
        hosts=ctx.result.hosts,
        open_ports=sum(len(h.open_services) for h in ctx.result.hosts),
        findings=ctx.findings,
        counts=counts,
        severities=SEVERITIES,
        diff=ctx.extras.get("diff"),
        warnings=ctx.warnings,
        generated=utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )


class ReportPlugin(Plugin):
    name = "report"
    description = "Write a self-contained HTML report (print it to PDF from the browser)"
    order = 110

    def add_arguments(self, group) -> None:
        group.add_argument("--output", metavar="FILE", help="Write an HTML report to FILE (e.g. report.html)")

    def is_enabled(self, args) -> bool:
        return bool(getattr(args, "output", None))

    def validate(self, args) -> None:
        parent = Path(args.output).resolve().parent
        if not parent.is_dir():
            raise PluginConfigError(f"Report directory does not exist: {parent}")

    def output(self, ctx) -> None:
        path = Path(ctx.args.output)
        path.write_text(render(ctx), encoding="utf-8")
        if not getattr(ctx.args, "quiet", False):
            from vain import ui

            ui.info(f"Report written to {path}")


PLUGIN = ReportPlugin
