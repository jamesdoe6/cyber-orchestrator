"""Report generation: rich Jinja2 HTML (+ optional WeasyPrint PDF).

Produces a consulting-grade, detailed report per engagement, themed by mode
(attack = crimson/amber, defense = cyan/emerald) on the portfolio's navy/azure
palette. PDF export is attempted via WeasyPrint; if its native deps are absent
the HTML is still produced.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..mitre import lookup
from ..models import AuditEvent, Engagement, Mode, Report, RunStatus, Severity
from ..security import audit as audit_mod

_TEMPLATES = settings.paths_data.parent / "app" / "reporting" / "templates"
_env = Environment(loader=FileSystemLoader(str(_TEMPLATES)),
                   autoescape=select_autoescape(["html", "xml"]))

_SEV_ORDER = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]
_SEV_COLOR = {Severity.critical: "#b00020", Severity.high: "#e24a00", Severity.medium: "#b8860b",
              Severity.low: "#0b5fbf", Severity.info: "#5a7184"}
_SEV_WEIGHT = {Severity.critical: 5, Severity.high: 4, Severity.medium: 3, Severity.low: 2, Severity.info: 1}


def _fmt_duration(a, b):
    if not a or not b:
        return "—"
    secs = (b - a).total_seconds()
    return f"{secs:.1f}s" if secs < 60 else f"{secs/60:.1f}min"


def _severity_bar(counts):
    rows = [(s, counts.get(s, 0)) for s in _SEV_ORDER]
    maxv = max((v for _, v in rows), default=0) or 1
    out = ['<svg width="100%" viewBox="0 0 520 180" role="img" aria-label="Findings by severity" preserveAspectRatio="xMinYMin meet">']
    y = 8
    for sev, val in rows:
        w = int(430 * val / maxv)
        out.append(f'<text x="0" y="{y+13}" font-size="12.5" font-weight="600" fill="#1e3a5f">{sev.value.title()}</text>')
        out.append(f'<rect x="78" y="{y}" width="430" height="18" rx="5" fill="#eef4fb"/>')
        if w:
            out.append(f'<rect x="78" y="{y}" width="{w}" height="18" rx="5" fill="{_SEV_COLOR[sev]}"/>')
        out.append(f'<text x="{78+max(w,0)+8}" y="{y+13}" font-size="12" font-weight="700" fill="{_SEV_COLOR[sev]}">{val}</text>')
        y += 33
    out.append("</svg>")
    return "".join(out)


def _donut(counts):
    total = sum(counts.values()) or 1
    segs, start = [], 0.0
    C = 2 * 3.14159265 * 52
    for sev in _SEV_ORDER:
        v = counts.get(sev, 0)
        if not v:
            continue
        frac = v / total
        segs.append((_SEV_COLOR[sev], C * frac, C * start))
        start += frac
    circles = "".join(
        f'<circle cx="70" cy="70" r="52" fill="none" stroke="{c}" stroke-width="22" '
        f'stroke-dasharray="{seg:.2f} {C-seg:.2f}" stroke-dashoffset="{-off:.2f}" transform="rotate(-90 70 70)"/>'
        for c, seg, off in segs)
    return (f'<svg width="140" height="140" viewBox="0 0 140 140" role="img" aria-label="Severity distribution">'
            f'<circle cx="70" cy="70" r="52" fill="none" stroke="#eef4fb" stroke-width="22"/>{circles}'
            f'<text x="70" y="66" text-anchor="middle" font-size="26" font-weight="800" fill="#0a2540">{sum(counts.values())}</text>'
            f'<text x="70" y="86" text-anchor="middle" font-size="10" fill="#5a7184" letter-spacing="1">FINDINGS</text></svg>')


def _risk_level(counts):
    if counts.get(Severity.critical): return ("CRITICAL", "#b00020")
    if counts.get(Severity.high): return ("HIGH", "#e24a00")
    if counts.get(Severity.medium): return ("MEDIUM", "#b8860b")
    if counts.get(Severity.low): return ("LOW", "#0b5fbf")
    return ("INFORMATIONAL", "#5a7184")


def _narrative(e, counts, runs, risk, techniques):
    total = sum(counts.values())
    verb = "offensive security assessment" if e.mode == Mode.attack else "defensive security review"
    n_done = sum(1 for r in runs if r.status == RunStatus.completed)
    n_blocked = sum(1 for r in runs if r.status == RunStatus.blocked)
    s = (f"This report documents a {verb} conducted under engagement "
         f"“{e.name}”. A total of {len(runs)} action(s) were launched "
         f"({n_done} completed, {n_blocked} refused by the scope guard), producing "
         f"{total} finding(s) across {len(techniques)} distinct MITRE ATT&CK technique(s). ")
    c = counts.get(Severity.critical, 0); h = counts.get(Severity.high, 0)
    if c or h:
        s += (f"The overall risk posture is assessed as {risk[0]}, driven by "
              f"{c} critical and {h} high-severity finding(s) that warrant prompt remediation. ")
    else:
        s += f"The overall risk posture is assessed as {risk[0]}; no critical or high-severity issues were identified. "
    if e.mode == Mode.defense:
        s += ("Prioritized remediation guidance is provided for each finding in the dedicated section below. ")
    return s


def generate_report(db: Session, engagement: Engagement) -> Report:
    db.refresh(engagement)
    findings = list(engagement.findings)
    runs = list(engagement.runs)
    counts = Counter(f.severity for f in findings)
    risk = _risk_level(counts)

    technique_ids = sorted({t for r in runs for t in r.attack_techniques} |
                           {f.attack_technique for f in findings if f.attack_technique})
    simulated = any((r.parsed or {}).get("_simulated") for r in runs)

    # Tactic coverage (grouped techniques)
    tactics = defaultdict(list)
    for tid in technique_ids:
        d = lookup(tid)
        tactics[d["tactic"]].append(d)
    tactic_coverage = [{"tactic": t, "techniques": sorted(v, key=lambda x: x["id"])}
                       for t, v in sorted(tactics.items())]

    # Findings view (full detail), grouped by severity
    def fview(f):
        d = lookup(f.attack_technique) if f.attack_technique else {"id": "", "name": "", "tactic": ""}
        return {"title": f.title, "severity": f.severity.value, "sev_color": _SEV_COLOR[f.severity],
                "description": f.description, "asset": f.asset, "cvss": f.cvss,
                "remediation": f.remediation, "evidence": f.evidence or {},
                "tech_id": d["id"], "tech_name": d["name"], "tech_tactic": d["tactic"]}
    findings_sorted = sorted(findings, key=lambda f: (_SEV_ORDER.index(f.severity), f.title))
    groups = []
    for sev in _SEV_ORDER:
        items = [fview(f) for f in findings_sorted if f.severity == sev]
        if items:
            groups.append({"severity": sev.value, "color": _SEV_COLOR[sev], "count": len(items), "items": items})

    # Per-category breakdown (needs plugin category -> look up from registry)
    from ..plugins import registry
    slug_cat = {p.meta.slug: p.meta.category for p in registry.all_plugins()}
    cat_counts = Counter(slug_cat.get(r.plugin, r.plugin) for r in runs)

    # Runs view with metrics
    runs_view = []
    for r in runs:
        runs_view.append({
            "plugin": r.plugin, "target": r.target, "status": r.status.value,
            "command": r.command, "exit_code": r.exit_code, "error": r.error,
            "duration": _fmt_duration(r.started_at, r.finished_at),
            "started": r.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if r.started_at else "—",
            "techniques": [lookup(t) for t in r.attack_techniques],
            "simulated": (r.parsed or {}).get("_simulated", False),
            "parsed": {k: v for k, v in (r.parsed or {}).items() if not k.startswith("_")},
            "findings_n": len(r.findings),
            "raw_output": (r.raw_output or "")[:6000],
        })

    # Audit excerpt for this engagement + chain verification
    chain = audit_mod.verify_chain(db)
    rows = db.execute(select(AuditEvent).where(AuditEvent.engagement_id == engagement.id)
                      .order_by(AuditEvent.id.asc())).scalars().all()
    audit_view = [{"ts": a.ts.strftime("%Y-%m-%d %H:%M:%S"), "action": a.action,
                   "actor": a.actor, "hash": a.entry_hash[:12], "detail": a.detail} for a in rows]

    kpis = {
        "actions_total": len(runs),
        "actions_completed": sum(1 for r in runs if r.status == RunStatus.completed),
        "actions_blocked": sum(1 for r in runs if r.status == RunStatus.blocked),
        "actions_failed": sum(1 for r in runs if r.status == RunStatus.failed),
        "findings_total": len(findings),
        "techniques_count": len(technique_ids),
        "assets_count": len({f.asset for f in findings if f.asset}),
        "simulated": simulated,
    }

    template_name = "attack.html" if engagement.mode == Mode.attack else "defense.html"
    html = _env.get_template(template_name).render(
        engagement=engagement, authorization=engagement.authorization,
        author=settings.report_author, org=settings.report_org,
        generated_at=datetime.now(timezone.utc),
        summary=_narrative(engagement, counts, runs, risk, technique_ids),
        risk_level=risk[0], risk_color=risk[1],
        counts={s.value: counts.get(s, 0) for s in _SEV_ORDER},
        sev_color={s.value: c for s, c in _SEV_COLOR.items()},
        severity_bar=_severity_bar(counts), donut=_donut(counts),
        groups=groups, tactic_coverage=tactic_coverage,
        category_breakdown=sorted(cat_counts.items(), key=lambda x: -x[1]),
        runs=runs_view, audit=audit_view, audit_chain=chain,
        kpis=kpis, simulated=simulated,
        mode=engagement.mode.value,
    )

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = settings.paths_reports / f"engagement-{engagement.id}-{ts}"
    html_path = base.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")

    pdf_path = ""
    try:
        from weasyprint import HTML
        pdf_file = base.with_suffix(".pdf")
        HTML(string=html).write_pdf(str(pdf_file))
        pdf_path = str(pdf_file)
    except Exception:  # noqa: BLE001
        pdf_path = ""

    report = Report(engagement_id=engagement.id, mode=engagement.mode,
                    html_path=str(html_path), pdf_path=pdf_path,
                    summary=_narrative(engagement, counts, runs, risk, technique_ids))
    db.add(report)
    db.commit()
    db.refresh(report)
    return report
