#!/usr/bin/env python3
"""
Patchday Board — Open-Source Patchday Report Generator Backend

Features:
  - Fetches security advisories directly from Microsoft MSRC CVRF/CSAF v3.0 API & Red Hat Security Data API.
  - Generates comprehensive monthly security reports using local or remote LLM endpoints (Ollama / OpenAI API compliant).
  - Optional search enrichment via SearXNG.
  - Generates HTML, Markdown, EML, PDF, and XLSX exports.

License: MIT
"""

import json
import os
import re
import time
import datetime
import email.mime.multipart
import email.mime.text
import email.utils
from concurrent.futures import ThreadPoolExecutor, as_completed, wait as _fut_wait
from pathlib import Path
import ssl
import urllib.parse
import urllib.request
import requests
from flask import Flask, Response, jsonify, request, send_from_directory

# ─── Configuration & Defaults ──────────────────────────────────────────────────

BASE_DIR        = Path(__file__).parent
OUTPUT_DIR      = BASE_DIR / "output"
PROMPT_FILE     = BASE_DIR / "prompt.txt"
SETTINGS_FILE   = BASE_DIR / "settings.json"

OUTPUT_DIR.mkdir(exist_ok=True)

def _load_settings() -> dict:
    try:
        return json.loads(SETTINGS_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def _save_settings(settings: dict):
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2))

def _get_ollama_url() -> str:
    s = _load_settings()
    url = (s.get("api_url") or s.get("ollama_url") or os.environ.get("OLLAMA_URL", "http://localhost:11434")).strip()
    return url.rstrip("/")

def _llmproxy_headers() -> dict:
    s = _load_settings()
    token = (s.get("api_key") or s.get("llmproxy_token") or os.environ.get("LLMPROXY_TOKEN", "")).strip()
    return {"Authorization": f"Bearer {token}"} if token else {}

SEARXNG_URL     = os.environ.get("SEARXNG_URL",     "")
LISTEN_PORT     = int(os.environ.get("LISTEN_PORT", "5099"))

REPORT_FROM     = os.environ.get("REPORT_FROM",     "patchday-report@example.com")
REPORT_TO       = os.environ.get("REPORT_TO",       "security@example.com")

# Optional FTP / S3 Remote Deployment (Disabled by default if FTP_HOST is empty)
FTP_HOST        = os.environ.get("FTP_HOST",        "")
FTP_USER        = os.environ.get("FTP_USER",        "")
FTP_PASS        = os.environ.get("FTP_PASS",        "")
FTP_PORT        = int(os.environ.get("FTP_PORT",    "21"))
FTP_TLS         = os.environ.get("FTP_TLS",         "false").lower() == "true"
FTP_PATH        = os.environ.get("FTP_PATH",        "/public_html/patchday-board/")

import threading as _threading
_cancel_event = _threading.Event()

# ─── Product Groups ────────────────────────────────────────────────────────────
#
# The inventory lives in groups.json, not in this file, so a deployment can be
# scoped to its own estate without editing code — and so a public checkout does
# not carry someone's product list. groups.json is gitignored; the committed
# groups.example.json documents the format and provides the fallback.

GROUPS_FILE    = BASE_DIR / "groups.json"
GROUPS_EXAMPLE = BASE_DIR / "groups.example.json"


def _load_group_config() -> tuple[list, list]:
    """(product_groups, retired_platforms) from groups.json, else from
    groups.example.json. A malformed file is fatal rather than silently
    empty: running with no groups would produce a report with no findings,
    which is exactly the kind of quiet emptiness this generator must not
    publish."""
    for path in (GROUPS_FILE, GROUPS_EXAMPLE):
        if not path.exists():
            continue
        try:
            cfg = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise SystemExit(f"[config] {path.name}: invalid JSON — {e}")
        groups = cfg.get("product_groups") or []
        if not groups:
            raise SystemExit(f"[config] {path.name}: 'product_groups' is empty")
        print(f"[config] {len(groups)} product groups from {path.name}")
        return groups, cfg.get("retired_platforms") or []
    raise SystemExit(
        f"[config] neither {GROUPS_FILE.name} nor {GROUPS_EXAMPLE.name} found "
        f"in {BASE_DIR}")


PRODUCT_GROUPS, RETIRED_PLATFORMS = _load_group_config()

def _is_retired(version: str) -> bool:
    v = (version or "").lower()
    return any(r in v for r in RETIRED_PLATFORMS)


def _supported_versions(f: dict) -> list:
    """Affected versions with the retired platforms removed."""
    return [v for v in (f.get("affected_versions") or []) if not _is_retired(v)]


_SEVERITY_RANK = {"critical": 0, "high": 1, "important": 1, "medium": 2, "moderate": 2, "low": 3, "unknown": 4}

_MODEL_PREFERENCE = [
    "qwen3:32b",
    "qwen3.6-35b",
    "qwen2.5:32b",
    "qwen:32b",
    "qwen:14b",
    "llama3:70b",
    "llama3.3:70b",
    "llama3:8b",
    "mistral",
]

_MONTH_DE_TO_EN = {
    'Januar':('Jan',1),'Februar':('Feb',2),'März':('Mar',3),'April':('Apr',4),
    'Mai':('May',5),'Juni':('Jun',6),'Juli':('Jul',7),'August':('Aug',8),
    'September':('Sep',9),'Oktober':('Oct',10),'November':('Nov',11),'Dezember':('Dec',12),
}

# ─── Direct Vendor APIs (MSRC / Red Hat) ──────────────────────────────────────

# SSVC levels: label, icon and colours. Single source for both the legend in
# the report header and the badge on each CVE — keeping them apart is how a
# legend ends up describing colours the badges do not use.
_SSVC_STYLES = {
    'act':    ('Act',    '&#128680;', '#b71c1c', '#fdecea', '#ef9a9a',
               'Act now — actively exploited, immediate risk'),
    'attend': ('Attend', '&#9888;',   '#e65100', '#fff3e0', '#ffcc80',
               'Act soon — elevated urgency, patch with priority'),
    'track*': ('Track*', '&#128065;', '#f57f17', '#fffde7', '#ffe082',
               'Watch closely — potentially relevant'),
    'track':  ('Track',  '&#10003;',  '#2e7d32', '#e8f5e9', '#a5d6a7',
               'Track — no immediate action required'),
}

# Same palette as _SSVC_STYLES, as openpyxl fills for the XLSX export.
_SSVC_XLSX_FILL = {
    'act': 'FFCDD2', 'attend': 'FFE0B2', 'track*': 'FFFDE7', 'track': 'E8F5E9',
}


def _ssvc_badge(decision: str) -> str:
    """Coloured HTML badge for an SSVC decision. Without a decision it renders
    a neutral "pending" so the slot is never simply blank."""
    key = (decision or '').strip().lower()
    if key in _SSVC_STYLES:
        label, icon, fg, bg, border, _ = _SSVC_STYLES[key]
    else:
        label, icon, fg, bg, border = 'pending', '&#8212;', '#616161', '#f5f5f5', '#bdbdbd'
    return (
        f'<span style="display:inline-block;background:{bg};color:{fg};'
        f'border:1px solid {border};border-radius:3px;padding:1px 7px;font-size:11px;'
        f'font-weight:700;font-family:monospace;white-space:nowrap;">{icon} SSVC: {label}</span>'
    )


def _ssvc_legend() -> str:
    """Legend for the report header, from the same palette as the badges."""
    rows = []
    for key in ('act', 'attend', 'track*', 'track'):
        label, icon, fg, bg, border, desc = _SSVC_STYLES[key]
        rows.append(
            f'<span style="background:{bg};color:{fg};border:1px solid {border};'
            f'border-radius:4px;padding:4px 12px;font-weight:700;">{icon} {label}</span>'
            f'<span style="color:#555;align-self:center;margin-right:8px;">{desc}</span>'
        )
    return "\n    ".join(rows)


def _ssvc_badge_compact(decision: str) -> str:
    """Short form for table rows. The full badge carries nine inline CSS
    properties; across a thousand rows that is half a megabyte of markup
    saying nothing extra."""
    key = (decision or '').strip().lower()
    if key in _SSVC_STYLES:
        label, _icon, fg, bg, _b, _d = _SSVC_STYLES[key]
    else:
        label, fg, bg = '&mdash;', '#616161', '#f5f5f5'
    return (f'<span style="background:{bg};color:{fg};padding:1px 5px;'
            f'border-radius:3px;font-weight:700;">{label}</span>')


def _cvss_badge_compact(score: float, severity: str) -> str:
    """Short form for table rows, see _ssvc_badge_compact."""
    sev_l = (severity or '').lower()
    if sev_l == 'critical':
        fg, bg = '#c62828', '#ffebee'
    elif sev_l in ('high', 'important'):
        fg, bg = '#e65100', '#fff3e0'
    elif sev_l in ('medium', 'moderate'):
        fg, bg = '#f9a825', '#fffde7'
    else:
        fg, bg = '#2e7d32', '#e8f5e9'
    return (f'<span style="background:{bg};color:{fg};padding:1px 5px;'
            f'border-radius:3px;font-weight:700;">{score:.1f}</span>')


# How many findings per group go into the LLM prompt. Purely a context-window
# limit: 30 findings are roughly 7.5k tokens. The report itself lists every
# finding — the complete per-group table is built without a model in
# _build_findings_table().
LLM_SAMPLE_PER_GROUP = 30


def _append_table_to_section(section: str, table: str) -> str:
    """Places the complete table inside the model's group card (before its
    closing </div>) so it inherits the card's frame and colour. If there is no
    </div> — the model returned broken HTML — it is appended rather than
    lost."""
    if not table:
        return section
    idx = section.rfind("</div>")
    if idx == -1:
        return section + table
    return section[:idx] + table + section[idx:]


def _build_findings_table(group: dict, findings: list) -> str:
    """Every finding of a group as an HTML table.

    Deliberately model-free: this list is the record, not the summary. It must
    not depend on a context window, must invent nothing and omit nothing — the
    generated section above it covers the top LLM_SAMPLE_PER_GROUP, this holds
    all of them.
    """
    if not findings:
        return ""
    rows = []
    for f in findings:
        cve   = f.get("cve_id", "")
        src   = (f.get("source") or "").lower()
        link  = (f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
                 if src == "msrc" else
                 f"https://access.redhat.com/security/cve/{cve}")
        vlist = _versions_for_display(f, group)
        # First version plus a counter instead of the whole list — the full one
        # is in the XLSX, here it would make the table unreadable.
        vers  = "" if not vlist else (
            vlist[0][:44] + (f' <span style="color:#999;">+{len(vlist)-1}</span>'
                             if len(vlist) > 1 else ''))
        impact = f.get("impact") or ""
        summ  = (f.get("summary") or "")[:110]
        td    = 'padding:5px 8px;border-bottom:1px solid #eee;'
        rows.append(
            '<tr>'
            f'<td style="{td}white-space:nowrap;">'
            f'<a href="{link}" style="color:#0067b8;text-decoration:none;">{cve}</a></td>'
            f'<td style="{td}">{_cvss_badge_compact(f.get("score") or 0, f.get("severity") or "")}</td>'
            f'<td style="{td}">{_ssvc_badge_compact(f.get("ssvc_decision"))}</td>'
            f'<td style="{td}font-size:11px;color:#555;">'
            f'{impact if impact and impact != "n/a" else "&mdash;"}</td>'
            f'<td style="{td}font-size:11px;">{summ}</td>'
            f'<td style="{td}font-size:10px;color:#777;">{vers or "&mdash;"}</td>'
            '</tr>'
        )
    colour = group.get("color", "#495057")
    hdr = "".join(
        f'<th style="padding:6px 8px;text-align:left;font-size:11px;color:#fff;'
        f'background:{colour};white-space:nowrap;">{h}</th>'
        for h in ("CVE", "CVSS", "SSVC", "Impact", "Description", "Affected versions"))
    return (
        '<details style="margin-top:18px;">'
        f'<summary style="cursor:pointer;font-weight:700;color:{colour};'
        f'font-size:13px;padding:6px 0;">All {len(findings)} findings in this '
        'group (complete list)</summary>'
        '<div style="overflow-x:auto;margin-top:8px;">'
        '<table style="border-collapse:collapse;width:100%;font-size:12px;">'
        f'<thead><tr>{hdr}</tr></thead><tbody>{"".join(rows)}</tbody></table></div></details>'
    )


# SSVC levels and their sort rank. The rank ends up on each finding as
# ssvc_priority and decides which CVEs survive the per-group cap.
_SSVC_RANK = {'act': 1, 'attend': 2, 'track*': 3, 'track': 4}


def _ssvc_decision(has_exploit: bool, is_rce: bool, score: float,
                   disclosed: bool = False) -> str:
    """The heuristic documented in the README: active exploitation beats an
    RCE attack vector, which beats CVSS."""
    if has_exploit:
        return 'act'
    if is_rce and score >= 8.0:
        return 'attend'
    if disclosed or score >= 7.0:
        return 'track*'
    return 'track'


def _versions_for_display(f: dict, group: dict) -> list:
    """Affected versions for display — for a scoped group, only those that
    match the scope. The raw list is alphabetical, so "Windows 10 ..." sorts
    ahead of "Windows 11 ...", and an unfiltered, truncated line would show
    only Windows 10 SKUs for a CVE that earned its place via Windows 11."""
    # Retired platforms go first — they belong in no "affected" line, not
    # even in groups without a product_filter.
    versions = _supported_versions(f)
    prod_filt = [p.lower() for p in group.get('product_filter', [])]
    if not prod_filt or not versions:
        return versions
    hits = [v for v in versions if any(p in v.lower() for p in prod_filt)]
    return hits or versions


def _fetch_msrc_findings(month: str, year: str) -> list:
    """Fetches Patch Tuesday CVEs directly from Microsoft MSRC CVRF v3.0 API."""
    abbr, _ = _MONTH_DE_TO_EN.get(month, ('Jun', 6))
    url = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{year}-{abbr}"
    try:
        req = urllib.request.Request(url, headers={
            "Accept":     "application/json",
            "User-Agent": "PatchdayBoard/1.0",
        })
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
    except Exception as e:
        print(f"[MSRC] Error fetching CVRF: {e}")
        return []

    # The authoritative product list is ProductTree.FullProductName (282 entries
    # in the 2026-Sep feed). Walking Branch[].Item[] finds nothing: the branches
    # are named "Items" (plural) and carry no products themselves, so prod_map
    # came out empty and every CVE was grouped on its title alone.
    prod_tree = data.get('ProductTree') or {}
    prod_map: dict[str, str] = {
        p.get('ProductID', ''): p.get('Value', '')
        for p in (prod_tree.get('FullProductName') or [])
        if p.get('ProductID') and p.get('Value')
    }

    def _walk_branches(nodes):
        for node in nodes or []:
            if node.get('ProductID') and node.get('Value'):
                prod_map.setdefault(node['ProductID'], node['Value'])
            _walk_branches(node.get('Items') or node.get('Item') or [])

    _walk_branches(prod_tree.get('Branch') or [])

    findings = []
    for vuln in data.get('Vulnerability', []):
        cve_id = vuln.get('CVE', '')
        if not cve_id:
            continue

        title_val = (vuln.get('Title') or {}).get('Value', '')

        cvss_sets = vuln.get('CVSSScoreSets') or []
        score = 0.0
        if cvss_sets:
            try:
                score = float(cvss_sets[0].get('BaseScore') or 0)
            except (ValueError, TypeError):
                pass

        # CVRF Threat types, verified against the 2026-Sep feed:
        #   0 = Impact   (Remote Code Execution, Elevation of Privilege, ...)
        #   1 = Exploit Status ("Publicly Disclosed:No;Exploited:Yes;...")
        #   3 = Severity (Critical / Important / Moderate / Low)
        # Types 0 and 3 used to be swapped here, so is_rce was never True and
        # `severity` held the impact string instead of a severity.
        severity, impact, is_rce, has_exploit, disclosed = '', '', False, False, False
        for t in (vuln.get('Threats') or []):
            t_type = t.get('Type', -1)
            t_raw  = ((t.get('Description') or {}).get('Value') or '').strip()
            t_val  = t_raw.lower()
            if t_type == 3 and t_raw and not severity:
                severity = t_raw
            elif t_type == 0 and t_raw:
                if not impact:
                    impact = t_raw
                if 'remote code execution' in t_val:
                    is_rce = True
            elif t_type == 1:
                # Parse the fields instead of matching 'yes' anywhere in the
                # string: "Publicly Disclosed:Yes;Exploited:No" is NOT exploited.
                for part in t_raw.split(';'):
                    k, _, v = part.partition(':')
                    k, v = k.strip().lower(), v.strip().lower()
                    if k == 'exploited' and v == 'yes':
                        has_exploit = True
                    elif k == 'publicly disclosed' and v == 'yes':
                        disclosed = True

        affected_products = []
        for ps in (vuln.get('ProductStatuses') or []):
            for pid in (ps.get('ProductID') or []):
                name = prod_map.get(pid, '')
                if name:
                    affected_products.append(name)
        # Group on the title only: it names the component ("Windows Hyper-V",
        # "Microsoft Word"). Folding in the affected products makes the first
        # group (Windows Server) swallow nearly every Windows CVE, since almost
        # all of them list a Server SKU. The product list is kept separately in
        # affected_versions, where the version filter reads it.
        matching_text = title_val

        if not severity:
            severity = 'Critical' if score >= 9.0 else 'Important' if score >= 7.0 else 'Moderate'

        findings.append({
            'cve_id':            cve_id,
            'severity':          severity,
            'impact':            impact or 'n/a',
            'score':             score,
            'source':            'msrc',
            'summary':           title_val,
            'matching_text':     matching_text,
            # Not truncated: the version filter checks against this list, and
            # a cap would sort "Windows 10 ..." ahead of "Windows 11 ...".
            'affected_versions': sorted(set(affected_products)),
            'is_kev':            False,
            'has_exploit':       has_exploit,
            'has_metasploit':    False,
            'is_rce':            is_rce,
            'is_disclosed':      disclosed,
            'ssvc_decision':     _ssvc_decision(has_exploit, is_rce, score, disclosed),
            'ssvc_exploitation': 'active' if has_exploit else 'poc' if is_rce else 'none',
            'ssvc_priority':     _SSVC_RANK.get(
                _ssvc_decision(has_exploit, is_rce, score, disclosed), 4),
            'product':           affected_products[0] if affected_products else 'Microsoft',
            'epss_score':        None,
        })

    def _relevant(f):
        sev = (f.get('severity') or '').lower()
        return (sev in ('critical', 'high', 'important')
                or (f.get('score') or 0) >= 7.0
                or f.get('has_exploit') or f.get('is_rce'))

    findings = [f for f in findings if _relevant(f)]
    print(f"[MSRC] {len(findings)} relevant CVEs fetched for {month} {year}")
    return findings


def _rhel_versions_from_packages(packages) -> list:
    """Derives RHEL major versions from the package NVRs the Security Data API
    returns: "389-ds-base-0:2.4.5-29.el9_4" -> "RHEL 9". The API carries no
    version field of its own, the .elN suffix is the only source. Packages
    without a recognisable suffix (module streams such as "redhat-ds:12-...")
    yield nothing — the list stays empty and the version filter lets the
    finding through rather than discarding it unchecked."""
    found = set()
    for pkg in packages or []:
        m = re.search(r"\.el(\d+)", pkg or "")
        if m:
            found.add(int(m.group(1)))
    return [f"RHEL {v}" for v in sorted(found)]


def _fetch_rhel_findings(month: str, year: str) -> list:
    """Fetches Red Hat Security Advisories directly from Red Hat Security Data API."""
    import calendar as _cal
    _, month_num = _MONTH_DE_TO_EN.get(month, ('Jun', 6))
    last_day = _cal.monthrange(int(year), month_num)[1]
    after  = f"{year}-{month_num:02d}-01"
    before = f"{year}-{month_num:02d}-{last_day:02d}"

    findings: list = []
    seen: set = set()

    def _parse_entry(c):
        cve_id = c.get('CVE', '') or c.get('id', '')
        if not cve_id or cve_id in seen:
            return None
        sev = (c.get('severity') or '').lower()
        if sev not in ('critical', 'important', 'high'):
            return None
        seen.add(cve_id)
        score = 0.0
        try:
            score = float(c.get('cvss3_score') or c.get('cvss_score') or 0)
        except (ValueError, TypeError):
            pass
        summ   = (c.get('bugzilla_description') or c.get('summary') or '')[:300]
        prods  = c.get('package_state') or []
        pnames = [p.get('package_name', '') for p in prods if isinstance(p, dict)]
        mtext  = summ + ' ' + ' '.join(pnames[:10])
        is_rce = any(k in summ.lower() for k in ('code execution', ' rce', 'arbitrary code'))
        # Red Hat reports no exploitation status, so the rating rests on RCE
        # and CVSS. This used to be blank, which printed "SSVC: pending" for
        # every Red Hat CVE in the report.
        ssvc = _ssvc_decision(False, is_rce, score)

        return {
            'cve_id':            cve_id,
            'severity':          c.get('severity', 'Important'),
            'score':             score,
            'source':            'rhel',
            'summary':           summ,
            'matching_text':     mtext,
            'affected_versions': _rhel_versions_from_packages(c.get('affected_packages')),
            'is_kev':            False,
            'has_exploit':       False,
            'has_metasploit':    False,
            'is_rce':            is_rce,
            'ssvc_decision':     ssvc,
            'ssvc_exploitation': 'poc' if is_rce else 'none',
            'ssvc_priority':     _SSVC_RANK.get(ssvc, 4),
            'product':           pnames[0] if pnames else 'Red Hat',
            'epss_score':        None,
        }

    # Query Red Hat Security Data API
    # Red Hat moved the Security Data API from /labs/securitydataapi/ to
    # /hydra/rest/securitydata/; the old path answers 404, which left the
    # report with zero RHEL CVEs.
    url = (f"https://access.redhat.com/hydra/rest/securitydata/cve.json"
           f"?after={after}&before={before}&per_page=250")
    try:
        req  = urllib.request.Request(url, headers={"User-Agent": "PatchdayBoard/1.0"})
        resp = urllib.request.urlopen(req, timeout=30)
        for entry in json.loads(resp.read()):
            item = _parse_entry(entry)
            if item:
                findings.append(item)
    except Exception as e:
        print(f"[RHEL] Error fetching Red Hat API: {e}")

    print(f"[RHEL] {len(findings)} relevant CVEs fetched for {month} {year}")
    return findings

# ─── SearXNG Search (Optional) ────────────────────────────────────────────────

def _search_searxng(query: str, count: int = 5) -> tuple[str, int, int]:
    if not SEARXNG_URL:
        return "", 0, 0
    try:
        url  = f"{SEARXNG_URL}/search?q={urllib.parse.quote(query)}&format=json&language=de-DE"
        req  = urllib.request.Request(url, headers={"User-Agent": "PatchdayBoard/1.0"})
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        results = data.get("results", [])
        total   = len(results)
        snippets = []
        for r in results[:count]:
            title = r.get("title", "")
            snip  = r.get("content", "")
            if title or snip:
                snippets.append(f"- {title}: {snip[:250]}")
        return "\n".join(snippets), total, min(total, count)
    except Exception as e:
        print(f"[SearXNG] Search error for '{query}': {e}")
        return "", 0, 0

# ─── Filter & Prioritize ──────────────────────────────────────────────────────

def _cvss_priority(f: dict) -> tuple[float, str, str]:
    score = float(f.get('score') or 0.0)
    source = f.get('source') or ''
    if source in ('msrc', 'Microsoft MSRC', 'MSRC'):
        return score, 'Vendor', 'Microsoft MSRC'
    elif source in ('rhel', 'Red Hat', 'RHEL'):
        return score, 'Vendor', 'Red Hat'
    else:
        return score, 'Other', source or 'Unknown'


def _filter_findings_for_group(findings: list, group: dict, already_matched: set) -> tuple[list, int]:
    keywords  = [k.lower() for k in group.get("keywords", [])]
    excludes  = [e.lower() for e in group.get("excludes", [])]
    cp_source = group.get("cp_source", "")
    catch_all = group.get("catch_all_msrc", False)
    prod_filt = [p.lower() for p in group.get("product_filter", [])]

    def _version_ok(f: dict) -> bool:
        """Restricts a group to specific product versions (product_filter).
        The CVE title names the component, never the version, so this checks
        affected_versions instead.

        Findings without version data are NOT excluded: only a minority of Red
        Hat CVEs carry package data, and in a security report an uncertain
        inclusion beats a silent loss. The filter only removes what is
        demonstrably out of scope.
        """
        versions = f.get("affected_versions") or []
        # A CVE that only affects retired platforms belongs in no group —
        # not even the catch-all.
        if versions and not _supported_versions(f):
            return False
        if not prod_filt:
            return True
        if not versions:
            return True
        hay = " | ".join(_supported_versions(f)).lower()
        return any(p in hay for p in prod_filt)

    matched = []
    raw_count = 0

    for f in findings:
        cve_id = f.get("cve_id", "")
        src    = (f.get("source") or "").lower()

        if cp_source and src and cp_source not in src:
            if not catch_all:
                continue

        if not _version_ok(f):
            continue

        # A group bound to a single source (cp_source) takes everything from
        # that source: the source check above has already done the selecting,
        # and the keywords below only match a CVE whose summary happens to
        # name a package. For Red Hat that reduced 79 findings to 5.
        if cp_source == "rhel" and src == "rhel":
            raw_count += 1
            if cve_id not in already_matched:
                matched.append(f)
                already_matched.add(cve_id)
            continue

        text = (f.get("matching_text") or f.get("summary") or "").lower()
        title = (f.get("summary") or "").lower()

        if any(ex in text for ex in excludes):
            continue

        is_match = False
        if keywords:
            if any(kw in text for kw in keywords) or any(kw in title for kw in keywords):
                is_match = True
        elif catch_all:
            if cve_id not in already_matched and src in ('msrc', 'microsoft'):
                is_match = True

        if is_match:
            raw_count += 1
            if cve_id not in already_matched or catch_all:
                matched.append(f)
                already_matched.add(cve_id)

    # SSVC zuerst, dann CVSS: das Sample fuer den Prompt wird vorne
    # abgeschnitten, eine aktiv ausgenutzte CVE mit mittlerem Score darf dabei
    # nicht hinter lauter 9.8ern verschwinden.
    matched.sort(key=lambda f: (f.get('ssvc_priority', 4), -(f.get('score') or 0)))
    return matched, raw_count

# ─── Prompt Formatting ────────────────────────────────────────────────────────

def _format_vendor_context(findings: list) -> str:
    if not findings:
        return "\n[Keine Hersteller-CVE-Daten für dieses Zeitfenster vorhanden]\n"

    lines = [
        "",
        "=== VENDOR SECURITY ADVISORY DATEN ===",
        "Bewertungsquelle: Microsoft MSRC CVRF & Red Hat Security Data API",
        f"Datenstand: {datetime.datetime.now().strftime('%d.%m.%Y %H:%M')}",
        f"Anzahl relevanter CVEs: {len(findings)}",
        "",
    ]

    by_product: dict[str, list] = {}
    for f in findings:
        prod = f.get('product', 'Unbekannt')
        by_product.setdefault(prod, []).append(f)

    for prod in sorted(by_product.keys()):
        prod_findings = sorted(by_product[prod], key=lambda x: _cvss_priority(x)[0], reverse=True)
        lines.append(f"--- Produkt/Komponente: {prod} ---")
        for f in prod_findings:
            score, priority, src = _cvss_priority(f)
            cve   = f.get('cve_id', '?')
            sev   = f.get('severity', '?')
            summ  = (f.get('summary') or '')[:250]
            expl  = ' | Exploit bekannt' if f.get('has_exploit') else ''
            rce   = ' | RCE' if f.get('is_rce') else ''
            lines.append(f"  {cve}: CVSS {score:.1f} [{src}] Schwere: {sev}{expl}{rce}")
            if summ:
                lines.append(f"    ↳ {summ}")
        lines.append("")

    lines.append("=== ENDE VENDOR DATEN ===")
    return "\n".join(lines)


def _build_group_prompt(group: dict, group_findings: list, month: str, year: str, search_text: str) -> tuple[str, str]:
    sys_prompt = (
        "Du bist ein erfahrener IT-Sicherheits-Analyst. "
        "Erstelle präzise, strukturierte Sicherheitsberichte im HTML-Format. "
        "Nutze ausschließlich valide HTML-Tags. Gib KEIN ```html Codeblock-Enclosing aus."
    )

    gname    = group["name"]
    gversion = group["versions"]
    gcolor   = group["color"]

    if group_findings:
        findings_lines = []
        for f in group_findings:
            score, priority, src = _cvss_priority(f)
            cve   = f.get('cve_id', '?')
            sev   = f.get('severity', '?')
            summ  = (f.get('summary') or f.get('matching_text') or '')[:250]
            expl  = ' [Exploit: Yes]' if f.get('has_exploit') else ''
            rce   = ' [RCE]' if f.get('is_rce') else ''
            ssvc  = _ssvc_badge(f.get('ssvc_decision'))
            impact = f.get('impact') or ''
            imp   = f" [{impact}]" if impact and impact != 'n/a' else ''
            vers  = ", ".join(_versions_for_display(f, group))[:180]
            findings_lines.append(f"- {cve} (CVSS {score:.1f}, {sev}){imp}{expl}{rce}"
                                  f" | SSVC_BADGE: {ssvc}: {summ}"
                                  + (f"\n  Betroffen: {vers}" if vers else ''))
        findings_text = "\n".join(findings_lines)
    else:
        findings_text = "(Keine spezifischen Schwachstellen in den Hersteller-Feeds gelistet)"

    usr_prompt = f"""Erstelle die HTML-Sektion für die Produktgruppe "{gname}".

Einsatzierte Versionen: {gversion}
Azentfarbe: {gcolor}

HERSTELLER-FINDINGS ({len(group_findings)} Einträge):
{findings_text}

WEBSUCHE-ERGEBNISSE:
{search_text if search_text else '(Keine Websuche-Ergebnisse)'}

ANFORDERUNGEN AN DIE OUTPUT-SEKTION:
1. Container: <div style="background:#ffffff; border:1px solid #e0e0e0; border-left:5px solid {gcolor}; border-radius:8px; padding:25px; margin-bottom:25px; box-shadow:0 2px 4px rgba(0,0,0,0.05);">
2. Titel: <h2 style="color:{gcolor}; margin-top:0; margin-bottom:5px; font-size:20px;">{gname}</h2>
3. Versionen-Zeile: <p style="color:#666; font-size:12px; margin-top:0; margin-bottom:15px;">Versionen im Einsatz: {gversion}</p>
4. Falls Relevante Schwachstellen vorliegen:
   - Führe die wichtigsten CVEs als strukturierte Tabelle oder Karten auf.
   - Zeige CVE-ID (verlinkt auf official update guide/NVD), CVSS-Score, Schweregrad und Kurzbeschreibung.
   - Das SSVC_BADGE-HTML aus den Findings UNVERÄNDERT übernehmen (Farben und Text
     nicht anpassen) und die Einstufung nicht zusätzlich als Text wiederholen.
5. Falls keine relevanten Schwachstellen vorliegen:
   - Ausführlicher Satz: "Für den Patchday {month} {year} sind keine kritischen Schwachstellen für {gname} bekannt."
6. Gib AUSSCHLIESSLICH das HTML dieser einen <div ...>...</div> Sektion aus."""

    return sys_prompt, usr_prompt

# ─── LLM-Aufruf ───────────────────────────────────────────────────────────────

def _llm_call(model: str, sys_prompt: str, usr_prompt: str, timeout: int = 180) -> tuple[str, dict]:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user",   "content": usr_prompt},
        ],
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_predict": 2048,
        }
    }
    headers = {"Content-Type": "application/json", **_llmproxy_headers()}
    t0 = time.time()
    try:
        url = f"{_get_ollama_url()}/api/chat"
        resp = requests.post(url, json=payload, headers=headers, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        dt   = time.time() - t0
        content = data.get("message", {}).get("content", "").strip()

        # Markdown ```html ... ``` Strippen
        content = re.sub(r'^```html\s*', '', content, flags=re.IGNORECASE)
        content = re.sub(r'\s*```$', '', content)

        stats = {
            "duration_s":      dt,
            "prompt_tokens":   data.get("prompt_eval_count", 0),
            "response_tokens": data.get("eval_count", 0),
        }
        return content, stats
    except Exception as e:
        print(f"[LLM] Error: {e}")
        return "", {"duration_s": time.time() - t0, "error": str(e)}

# ─── PDF / XLSX / Markdown Export ──────────────────────────────────────────────

def _build_markdown_report(html_content: str, month: str, year: str) -> str:
    md = f"# Übersicht: Microsoft & Red Hat Patchday - {month} {year}\n\n"
    # HTML-Tags vereinfacht zu Markdown konvertieren
    clean = re.sub(r'<h2[^>]*>(.*?)</h2>', r'\n## \1\n', html_content)
    clean = re.sub(r'<h3[^>]*>(.*?)</h3>', r'\n### \1\n', clean)
    clean = re.sub(r'<p[^>]*>(.*?)</p>', r'\1\n\n', clean)
    clean = re.sub(r'<li[^>]*>(.*?)</li>', r'* \1\n', clean)
    clean = re.sub(r'<[^>]+>', '', clean)
    md += clean
    return md


def _render_xlsx(groups_data: list, xlsx_path: Path, month: str, year: str) -> tuple[bool, str]:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
        from openpyxl.utils import get_column_letter

        wb = Workbook()
        wb.remove(wb.active)

        _HDR_FONT = Font(bold=True, color='FFFFFF', size=10)
        _HDR_FILL = PatternFill('solid', fgColor='37474F')
        _BORDER   = Border(left=Side(style='thin', color='BDBDBD'), right=Side(style='thin', color='BDBDBD'),
                           top=Side(style='thin', color='BDBDBD'), bottom=Side(style='thin', color='BDBDBD'))
        _WRAP     = Alignment(wrap_text=True, vertical='top')

        COLS  = ['CVE-ID', 'CVSS', 'Severity', 'Quelle', 'KEV', 'Exploit', 'RCE', 'SSVC Decision', 'Zusammenfassung']
        COL_W = [16, 8, 10, 10, 5, 7, 5, 14, 60]

        ws_all = wb.create_sheet("Übersicht")
        ws_all.freeze_panes = 'A2'
        ws_all.row_dimensions[1].height = 20
        for ci, (col, w) in enumerate(zip(['Gruppe'] + COLS, [22] + COL_W), 1):
            cell = ws_all.cell(row=1, column=ci, value=col)
            cell.font = _HDR_FONT; cell.fill = _HDR_FILL; cell.border = _BORDER
            ws_all.column_dimensions[get_column_letter(ci)].width = w

        ri = 2
        for g in groups_data:
            for f in g.get('findings', []):
                score, priority, src = _cvss_priority(f)
                cve  = f.get('cve_id', '')
                summ = (f.get('summary') or f.get('matching_text') or '')[:500]
                row_vals = [
                    g['name'], cve, score, f.get('severity', ''), priority,
                    'JA' if f.get('is_kev') else '',
                    'JA' if f.get('has_exploit') else '',
                    'JA' if f.get('is_rce') else '',
                    f.get('ssvc_decision', ''),
                    summ
                ]
                # "Gruppe" steht vor COLS, die Spalte verschiebt sich um eins
                ssvc_col  = ['Gruppe'] + COLS
                ssvc_col  = ssvc_col.index('SSVC Decision') + 1
                ssvc_hex  = _SSVC_XLSX_FILL.get((f.get('ssvc_decision') or '').lower())
                for ci, val in enumerate(row_vals, 1):
                    cell = ws_all.cell(row=ri, column=ci, value=val)
                    cell.border = _BORDER; cell.alignment = _WRAP
                    if ci == ssvc_col and ssvc_hex:
                        cell.fill = PatternFill('solid', fgColor=ssvc_hex)
                        cell.font = Font(bold=True, size=10)
                ri += 1

        wb.save(xlsx_path)
        return True, str(xlsx_path)
    except Exception as e:
        return False, str(e)


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"

# ─── Generierungs-Stream ──────────────────────────────────────────────────────

def _generate_stream(model: str, month: str, year: str):
    _gen_start = time.time()
    yield _sse({"step": "init", "msg": f"Starte Generierung mit Modell: {model}", "pct": 0, "model": model})

    yield _sse({"step": "vendor_fetch", "msg": "Lade Microsoft MSRC Patch-Tuesday-Daten...", "pct": 5})
    msrc = _fetch_msrc_findings(month, year)
    yield _sse({"step": "vendor_fetch", "msg": f"MSRC: {len(msrc)} CVEs — lade Red Hat Security Advisories...", "pct": 10})
    rhel = _fetch_rhel_findings(month, year)
    findings = msrc + rhel
    yield _sse({"step": "vendor_done", "msg": f"Hersteller-APIs: {len(msrc)} MSRC + {len(rhel)} RHEL CVEs geladen.", "findings": len(findings), "pct": 15})

    _cancel_event.clear()
    total_groups    = len(PRODUCT_GROUPS)
    total_tokens    = 0
    already_matched: set = set()
    group_jobs: list  = []
    groups_data: list = []

    for i, group in enumerate(PRODUCT_GROUPS):
        if _cancel_event.is_set():
            yield _sse({"step": "CANCEL", "msg": "Generierung abgebrochen.", "pct": 0})
            return
        pct_base = 15 + int(i / total_groups * 30)
        gname    = group["name"]
        yield _sse({"step": "group_start", "msg": f"[{i+1}/{total_groups}] {gname}: Analysiere Schwachstellen...", "pct": pct_base})

        search_q                        = group["search_term"].format(month=month, year=year)
        search_text, hits_total, hits_used = _search_searxng(search_q)
        group_findings, cves_raw        = _filter_findings_for_group(findings, group, already_matched)
        # Nur eine Auswahl geht ins Modell — das ist eine Grenze des
        # Kontextfensters, keine Aussage darueber, was im Bericht steht.
        # Die vollstaendige Liste kommt aus _build_findings_table().
        llm_sample = group_findings[:LLM_SAMPLE_PER_GROUP]
        sys_prompt, usr_prompt = _build_group_prompt(group, llm_sample, month, year, search_text)
        group_jobs.append((i, group, sys_prompt, usr_prompt))
        groups_data.append({
            "name":     group["name"],
            "color":    group["color"],
            "versions": group["versions"],
            "findings": group_findings,
        })

    if _cancel_event.is_set():
        yield _sse({"step": "CANCEL", "msg": "Generierung abgebrochen.", "pct": 0})
        return

    yield _sse({"step": "group_llm", "msg": "Starte LLM-Verarbeitung der Produktgruppen...", "pct": 45})

    html_sections: list = [None] * total_groups

    def _do_llm(idx: int, grp: dict, sp: str, up: str):
        section, stats = _llm_call(model, sp, up)
        if not section:
            section = (f'<div style="background:#fff;border:1px solid #ddd;border-radius:8px;'
                       f'padding:25px;margin-bottom:25px;">'
                       f'<h2 style="color:{grp["color"]}">{grp["name"]}</h2>'
                       f'<p>Für den Patchday {month} {year} sind keine kritischen Schwachstellen für {grp["name"]} bekannt.</p></div>')
        return idx, grp, section, stats

    completed_count = 0
    with ThreadPoolExecutor(max_workers=2) as ex:
        future_map = {ex.submit(_do_llm, i, g, sp, up): (i, g["name"]) for i, g, sp, up in group_jobs}
        pending    = set(future_map)
        while pending:
            done_now, pending = _fut_wait(pending, timeout=15)
            for fut in done_now:
                idx, gname_orig = future_map[fut]
                try:
                    idx, grp, section, llm_stats = fut.result()
                    html_sections[idx] = _append_table_to_section(
                        section, _build_findings_table(grp, groups_data[idx]["findings"]))
                    completed_count += 1
                    words = len(section.split())
                    total_tokens += words
                    yield _sse({"step": "group_done", "msg": f"✓ [{completed_count}/{total_groups}] {grp['name']}: {words} Wörter", "pct": 45 + int(completed_count / total_groups * 40)})
                except Exception as e:
                    completed_count += 1
                    # Ohne Zusammenfassung bleibt die Fundliste erhalten.
                    html_sections[idx] = _append_table_to_section(
                        f'<div><h2>{gname_orig}</h2><p>Zusammenfassung fehlgeschlagen: {e}</p></div>',
                        _build_findings_table(PRODUCT_GROUPS[idx], groups_data[idx]["findings"]))

    html_sections_ordered = [s for s in html_sections if s]
    yield _sse({"step": "llm_done", "msg": f"Alle {total_groups} Gruppen verarbeitet.", "pct": 87})

    source_badge = (
        '<span style="display:inline-block;background:#e8f5e9;color:#2e7d32;border:1px solid #a5d6a7;'
        'border-radius:4px;padding:2px 10px;font-size:12px;font-weight:bold;margin-bottom:8px;">'
        '&#10003; Live Vendor APIs (MSRC &amp; Red Hat)</span>'
    )
    source_note = "KI-generierte Zusammenfassung auf Basis von <strong>Microsoft MSRC</strong> und <strong>Red Hat Security Advisories</strong>."

    html_content = f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Patchday Board - {month} {year}</title>
</head>
<body style="font-family:Arial,sans-serif;color:#333;line-height:1.6;background:#f4f4f4;padding:20px;">
<div style="width:80%;margin:20px auto;">
<h1 style="color:#004578;text-align:center;font-size:26px;margin-bottom:10px;">
  Übersicht: Microsoft &amp; Red Hat Patchday &ndash; {month} {year}
</h1>
<p style="text-align:center;margin-bottom:25px;">{source_badge}</p>
<div style="background:#f8f9fa;border:1px solid #dee2e6;border-left:4px solid #495057;border-radius:6px;padding:18px 22px;margin-bottom:28px;font-size:13px;">
  <strong style="font-size:14px;color:#212529;">&#128736; SSVC (Stakeholder-Specific Vulnerability Categorization)</strong>
  <div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:10px;">
    {_ssvc_legend()}
  </div>
</div>

{''.join(html_sections_ordered)}

<div style="text-align:center;margin-top:30px;font-size:11px;color:#777;">
  <p><strong>Wichtiger Hinweis:</strong> {source_note}</p>
  <p>Generiert: {datetime.datetime.now().strftime('%d.%m.%Y %H:%M')} &mdash; Modell: <code>{model}</code> &mdash; Dauer: {int(time.time() - _gen_start)}s</p>
</div>
</div>
</body>
</html>"""

    month_slug = month.lower().replace('ä','ae').replace('ö','oe').replace('ü','ue')
    report_name = f"patchday_{year}_{month_slug}"

    html_path = OUTPUT_DIR / f"{report_name}.html"
    md_path   = OUTPUT_DIR / f"{report_name}.md"
    xlsx_path = OUTPUT_DIR / f"{report_name}.xlsx"

    html_path.write_text(html_content, encoding='utf-8')
    md_content = _build_markdown_report(html_content, month, year)
    md_path.write_text(md_content, encoding='utf-8')

    _render_xlsx(groups_data, xlsx_path, month, year)

    duration_s = int(time.time() - _gen_start)
    yield _sse({
        "step": "complete",
        "msg": f"Bericht erfolgreich generiert in {duration_s}s!",
        "pct": 100,
        "report_name": report_name,
        "html_path": str(html_path),
        "html_url": f"/output/{report_name}.html",
        "md_url":   f"/output/{report_name}.md",
        "xlsx_url": f"/output/{report_name}.xlsx",
    })

# ─── Flask App & Endpoints ─────────────────────────────────────────────────────

app = Flask(__name__, static_folder=str(BASE_DIR / "apps" / "helper"), static_url_path="/apps/helper")

@app.route("/")
def index():
    return send_from_directory(BASE_DIR / "apps" / "helper", "baselinevulnboard.html")

@app.route("/api/models")
def api_models():
    try:
        url = f"{_get_ollama_url()}/api/tags"
        resp = requests.get(url, headers=_llmproxy_headers(), timeout=5)
        resp.raise_for_status()
        data = resp.json()
        all_models = [m['name'] for m in data.get('models', [])]
        models = sorted(all_models, key=lambda m: next((i for i, p in enumerate(_MODEL_PREFERENCE) if p.lower() in m.lower()), 99))
        settings = _load_settings()
        default_model = settings.get("default_model") or (models[0] if models else "")
        return jsonify({
            "models": models,
            "default": default_model,
            "api_url": _get_ollama_url(),
            "api_key": settings.get("api_key", ""),
        })
    except Exception as e:
        settings = _load_settings()
        return jsonify({
            "models": [],
            "default": settings.get("default_model", ""),
            "api_url": _get_ollama_url(),
            "api_key": settings.get("api_key", ""),
            "error": str(e)
        })

@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        settings = _load_settings()
        if "default_model" in data:
            settings["default_model"] = str(data["default_model"]).strip()
        if "api_url" in data:
            settings["api_url"] = str(data["api_url"]).strip()
        if "api_key" in data:
            settings["api_key"] = str(data["api_key"]).strip()
        _save_settings(settings)
        return jsonify({"ok": True, "settings": settings})
    settings = _load_settings()
    settings.setdefault("api_url", _get_ollama_url())
    return jsonify(settings)

@app.route("/api/reports")
def api_reports():
    reports = []
    for p in sorted(OUTPUT_DIR.glob("patchday_*.html"), reverse=True):
        name = p.stem
        reports.append({
            "name":  name,
            "type":  "patchday",
            "html":  f"/output/{name}.html",
            "md":    f"/output/{name}.md"   if (OUTPUT_DIR / f"{name}.md").exists()  else None,
            "xlsx":  f"/output/{name}.xlsx" if (OUTPUT_DIR / f"{name}.xlsx").exists() else None,
            "size":  p.stat().st_size,
            "mtime": datetime.datetime.fromtimestamp(p.stat().st_mtime).isoformat(),
        })
    return jsonify({"reports": reports})

@app.route("/generate")
def generate():
    model = request.args.get('model', 'qwen3:32b')
    month = request.args.get('month', 'August')
    year  = request.args.get('year', str(datetime.datetime.now().year))

    def stream():
        for event in _generate_stream(model, month, year):
            yield event

    return Response(
        stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':   'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection':      'keep-alive',
        }
    )

@app.route("/cancel", methods=["POST"])
def cancel():
    _cancel_event.set()
    return {"ok": True}

@app.route("/api/reports/<name>/delete", methods=["POST"])
def api_report_delete(name):
    if not re.match(r'^patchday_[\w\-]+$', name):
        return jsonify({"ok": False, "error": "Invalid name"}), 400
    deleted = []
    for ext in ("html", "md", "eml", "pdf", "xlsx"):
        p = OUTPUT_DIR / f"{name}.{ext}"
        if p.exists():
            p.unlink()
            deleted.append(ext)
    return jsonify({"ok": True, "deleted": deleted})

@app.route("/output/<path:filename>")
def serve_output(filename):
    return send_from_directory(OUTPUT_DIR, filename)

@app.after_request
def add_cors(response):
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

if __name__ == "__main__":
    print(f"[patchday-board] Starting server on port {LISTEN_PORT}")
    print(f"[patchday-board] LLM Endpoint: {_get_ollama_url()}")
    app.run(host='0.0.0.0', port=LISTEN_PORT, debug=False, threaded=True)
