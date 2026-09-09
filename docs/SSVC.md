# SSVC in Patchday Board

How this project arrives at an SSVC rating: which fields it reads, which rules
it applies, and where the limits are.

The code in `patchday_backend.py` is authoritative; this document describes it
rather than replacing it.

---

## 1. What "SSVC" means here — and what it does not

SSVC (*Stakeholder-Specific Vulnerability Categorization*, CISA/SEI) is a
decision tree, not a score. It leads across several axes to one of four
recommendations:

| Level | Meaning | Urgency |
|---|---|---|
| **Act** | Act now — actively exploited, immediate risk | patch out of band |
| **Attend** | Act soon — elevated urgency | prioritise in the next cycle |
| **Track\*** | Watch closely — potentially relevant | monitor, re-evaluate |
| **Track** | Track — no immediate action required | normal patch cycle |

**This project implements a deliberately reduced heuristic, not the full
tree.** It reads what the vendor feeds actually provide: exploitation status,
attack type and CVSS. The remaining SSVC axes need signals the feeds do not
carry — see [Limits](#7-limits).

Ratings produced here are therefore **not comparable** with ratings from a
full SSVC implementation that has richer inputs.

---

## 2. Sources and input fields

### 2.1 Microsoft MSRC — CVRF v3.0

Endpoint: `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<YYYY>-<Mon>`

| Value | Origin in the feed | Derivation |
|---|---|---|
| `score` | `Vulnerability.CVSSScoreSets[0].BaseScore` | first score set, no aggregation |
| `severity` | `Threats[]` where `Type == 3` | first non-empty value (Critical / Important / Moderate / Low) |
| `impact` | `Threats[]` where `Type == 0` | first non-empty value (Remote Code Execution, Elevation of Privilege, …) |
| `is_rce` | `Threats[]` where `Type == 0` | true if an impact entry contains `remote code execution` |
| `has_exploit` | `Threats[]` where `Type == 1` | field `Exploited` == `Yes` |
| `is_disclosed` | `Threats[]` where `Type == 1` | field `Publicly Disclosed` == `Yes` |

The type mapping is verified against the `2026-Sep` feed. **Type 0 is the
impact, type 3 is the severity** — not the other way round.

Exploit status arrives as a compound string such as
`Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected`.
It is split **field by field**. Searching the whole string for `yes` would
misread `Publicly Disclosed:Yes;Exploited:No` as exploited.

### 2.2 Red Hat — Security Data API

Endpoint: `https://access.redhat.com/hydra/rest/securitydata/cve.json`

| Value | Origin | Derivation |
|---|---|---|
| `severity` | `severity` | only `critical`, `important`, `high` are kept, everything else is dropped |
| `score` | `cvss3_score`, else `cvss_score` | 0.0 if both are missing |
| `is_rce` | `bugzilla_description` | text search for `code execution`, ` rce`, `arbitrary code` |
| `has_exploit` | — | **always `False`**; the API carries no exploitation status |

---

## 3. The decision function

```python
def _ssvc_decision(has_exploit, is_rce, score, disclosed=False):
    if has_exploit:                 return 'act'
    if is_rce and score >= 8.0:     return 'attend'
    if disclosed or score >= 7.0:   return 'track*'
    return 'track'
```

As a sequence:

| # | Condition | Result | Rationale |
|---|---|---|---|
| 1 | `has_exploit` | **act** | exploitation is established — no other signal relativises it |
| 2 | `is_rce` and `score >= 8.0` | **attend** | remote code execution at a high base score |
| 3 | `disclosed` or `score >= 7.0` | **track\*** | publicly known, or a high base score — watch it |
| 4 | otherwise | **track** | normal cycle |

The order is the statement: **exploitation beats attack vector, which beats
CVSS.** An actively exploited flaw at CVSS 6.5 outranks a theoretical one
at 9.8.

### 3.1 What actually arrives per source

| Source | `has_exploit` | `is_rce` | `score` | reachable levels |
|---|---|---|---|---|
| MSRC | from feed | from feed | from feed | act, attend, track\*, track |
| Red Hat | never | text heuristic | from feed | attend, track\*, track |

**Red Hat never reaches `act`.** Not because nothing there is exploited, but
because the API does not carry that information. Treat the absence as unknown,
not as evidence of safety.

### 3.2 The relevance filter comes first

A filter decides what enters the report at all, before any rating happens:

```
MSRC:  severity in {critical, high, important}  OR  score >= 7.0
       OR has_exploit  OR  is_rce
RHEL:  severity in {critical, important, high}
```

Whatever is dropped here gets no SSVC level and never appears. The distribution
of levels in a report therefore describes **the filtered subset, not the feed**.

---

## 4. Priority, sorting and selection

The level becomes a numeric rank:

```python
_SSVC_RANK = {'act': 1, 'attend': 2, 'track*': 3, 'track': 4}
```

It is stored on the finding as `ssvc_priority` and has two effects.

**Sorting within a product group** — `(ssvc_priority, -score)`, so SSVC before
CVSS.

**Selection for the summary** — only the first `LLM_SAMPLE_PER_GROUP`
(currently 30) findings of a group go into the LLM prompt. That is a
context-window limit. The **complete list** appears regardless, in the
collapsible per-group table and in the XLSX, both built without a model.

Sorting by SSVC first is not cosmetic. Under pure CVSS sorting an actively
exploited CVE at 7.8 dropped out of the summary in September 2026, because
thirty entries at 9.8 sat ahead of it.

---

## 5. Presentation

Colour and label come from one definition (`_SSVC_STYLES`), which feeds both
the legend in the report header and the badges on individual CVEs — legend and
badge cannot drift apart.

| Level | Text | Background | XLSX fill |
|---|---|---|---|
| Act | `#b71c1c` | `#fdecea` | `FFCDD2` |
| Attend | `#e65100` | `#fff3e0` | `FFE0B2` |
| Track\* | `#f57f17` | `#fffde7` | `FFFDE7` |
| Track | `#2e7d32` | `#e8f5e9` | `E8F5E9` |

Without a rating a neutral "pending" is shown rather than an empty slot. In the
XLSX the `SSVC Decision` column is filled accordingly.

---

## 6. Configuration

The rating itself is not configurable — it is a function of the feed data.
What *is* configurable, in `groups.json`, is which findings reach it:

- `product_groups[].product_filter` restricts a group to specific product
  versions.
- `retired_platforms` removes decommissioned platforms across all groups; a CVE
  affecting only those never enters the report and therefore gets no rating.

See `groups.example.json` and the README.

---

## 7. Limits

**The Mission & Well-being axis is absent.** Real SSVC weighs the business
value of the affected system. The vendor feeds carry no such mapping, so this
implementation rates the vulnerability, not its relevance to a particular host.
Two machines with the same CVE get the same level, whether one is a domain
controller and the other a test box.

**Automatable and Technical Impact are not separate axes here.** `is_rce`
combined with `score >= 8.0` is a coarse stand-in for both.

**`is_rce` for Red Hat is a text heuristic.** It searches three substrings in
the Bugzilla description. An RCE described differently is missed; a description
mentioning "code execution" in passing is caught falsely.

**Ratings are a snapshot.** An exploit published after the run does not change
them retroactively. The report footer carries generation time and model.

---

## 8. Where to verify

| What | Where |
|---|---|
| Decision function | `_ssvc_decision()` in `patchday_backend.py` |
| Rank and sorting | `_SSVC_RANK`, `_filter_findings_for_group()` |
| MSRC field derivation | `_fetch_msrc_findings()` |
| Red Hat field derivation | `_fetch_rhel_findings()`, therein `_parse_entry()` |
| Colours and legend | `_SSVC_STYLES`, `_ssvc_badge()`, `_ssvc_legend()` |
| Complete findings list | `_build_findings_table()` |

Every individual rating can be checked against the report itself: the per-group
table shows CVSS, SSVC and impact side by side, and the XLSX adds the `KEV`,
`Exploit` and `RCE` flags.
