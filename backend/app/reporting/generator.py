"""Report generation: Jinja2 HTML (+ optional WeasyPrint PDF).

Each engagement renders to a consulting-grade HTML report themed by mode
(attack = red/orange, defense = blue/green). PDF export is attempted via
WeasyPrint; if its native dependencies are unavailable the HTML is still
produced and the PDF path is left empty rather than failing the request.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

from ..config import settings
from ..mitre import enrich
from ..models import Engagement, Mode, Report, Severity

_TEMPLATES = settings.paths_data.parent / "app" / "reporting" / "templates"
_env = Environment(loader=FileSystemLoader(str(_TEMPLATES)),
                   autoescape=select_autoescape(["html", "xml"]))

_SEV_ORDER = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]
_SEV_COLOR = {
    Severity.critical: "#b00020", Severity.high: "#e24a00", Severity.medium: "#d79f00",
    Severity.low: "#2e7d32", Severity.info: "#607d8b",
}


def _severity_chart(counts: dict[Severity, int]) -> str:
    """Inline SVG horizontal bar chart of findings by severity."""
    rows = [(s, counts.get(s, 0)) for s in _SEV_ORDER]
    maxv = max((v for _, v in rows), default=0) or 1
    bar_w = 320
    out = ['<svg width="520" height="190" role="img" aria-label="Findings by severity">']
    y = 10
    for sev, val in rows:
        w = int(bar_w * val / maxv)
        out.append(f'<text x="0" y="{y+14}" font-size="13" fill="currentColor">{sev.value.title()}</text>')
        out.append(f'<rect x="90" y="{y+2}" width="{w}" height="18" rx="3" fill="{_SEV_COLOR[sev]}"/>')
        out.append(f'<text x="{90+w+6}" y="{y+16}" font-size="13" fill="currentColor">{val}</text>')
        y += 30
    out.append("</svg>")
    return "".join(out)


def _summary_text(engagement: Engagement, counts: dict[Severity, int], run_count: int) -> str:
    total = sum(counts.values())
    hi = counts.get(Severity.critical, 0) + counts.get(Severity.high, 0)
    verb = "offensive assessment" if engagement.mode == Mode.attack else "defensive review"
    line = (f"This {verb} comprised {run_count} action(s) and produced {total} finding(s)")
    if hi:
        line += f", including {hi} of high or critical severity requiring prompt attention."
    else:
        line += ", none of high or critical severity."
    return line


def generate_report(db: Session, engagement: Engagement) -> Report:
    db.refresh(engagement)
    findings = list(engagement.findings)
    runs = list(engagement.runs)
    counts = Counter(f.severity for f in findings)

    technique_ids = sorted({t for r in runs for t in r.attack_techniques} |
                           {f.attack_technique for f in findings if f.attack_technique})
    simulated = any(r.parsed.get("_simulated") for r in runs if r.parsed)

    template_name = "attack.html" if engagement.mode == Mode.attack else "defense.html"
    html = _env.get_template(template_name).render(
        engagement=engagement,
        authorization=engagement.authorization,
        author=settings.report_author,
        org=settings.report_org,
        generated_at=datetime.now(timezone.utc),
        runs=runs,
        findings=sorted(findings, key=lambda f: _SEV_ORDER.index(f.severity)),
        counts={s.value: counts.get(s, 0) for s in _SEV_ORDER},
        severity_chart=_severity_chart(counts),
        attack_matrix=enrich(technique_ids),
        summary=_summary_text(engagement, counts, len(runs)),
        simulated=simulated,
        severities=[s.value for s in _SEV_ORDER],
        sev_color={s.value: c for s, c in _SEV_COLOR.items()},
    )

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    base = settings.paths_reports / f"engagement-{engagement.id}-{ts}"
    html_path = base.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")

    pdf_path = ""
    try:
        from weasyprint import HTML  # imported lazily: heavy native deps

        pdf_file = base.with_suffix(".pdf")
        HTML(string=html).write_pdf(str(pdf_file))
        pdf_path = str(pdf_file)
    except Exception:  # noqa: BLE001 - PDF is optional; HTML always succeeds
        pdf_path = ""

    report = Report(
        engagement_id=engagement.id, mode=engagement.mode,
        html_path=str(html_path), pdf_path=pdf_path,
        summary=_summary_text(engagement, counts, len(runs)),
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report
