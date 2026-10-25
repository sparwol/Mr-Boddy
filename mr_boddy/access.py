"""Mr. Boddy: third-party blast radius + shadow AI discovery.

Both answer one question: which outside services can touch our data, and did we
approve them? Unapproved AI services found in traffic are folded into the vendor
map as "unvetted" third parties so they are ranked alongside contracted vendors.
"""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .util import _read, _yes, _d

HERE = Path(__file__).parent


def _split(v: str) -> list[str]:
    return [x.strip() for x in (v or "").split(";") if x.strip()]


# ====================================================================== shadow AI
def load_catalog(path: Path | None = None) -> list[dict]:
    return json.loads(Path(path or HERE / "ai_catalog.json").read_text())["services"]


def _match(host: str, catalog: list[dict]) -> dict | None:
    host = host.lower().rstrip(".")
    for svc in catalog:
        for dom in svc["domains"]:
            if host == dom or host.endswith("." + dom):
                return svc
    return None


def shadow_ai(proxy_csv, oauth_csv, ai_policy_csv, pol: dict, catalog=None) -> list[dict]:
    p = pol["access"]
    catalog = catalog or load_catalog()
    status = {r["service_id"]: r for r in _read(ai_policy_csv)} if ai_policy_csv else {}
    agg: dict[str, dict] = {}

    def entry(svc):
        return agg.setdefault(svc["id"], {
            "service_id": svc["id"], "name": svc["name"], "vendor": svc["vendor"], "category": svc["category"],
            "policy_status": status.get(svc["id"], {}).get("status", "unreviewed"),
            "policy_notes": status.get(svc["id"], {}).get("notes", ""),
            "users": set(), "departments": defaultdict(set), "requests": 0, "bytes_out": 0,
            "large_uploads": [], "first_seen": None, "last_seen": None, "oauth_grants": [],
        })

    for r in _read(proxy_csv):
        svc = _match(r["dest_host"], catalog)
        if not svc:
            continue
        e = entry(svc)
        e["users"].add(r["user"]); e["departments"][r["department"]].add(r["user"])
        e["requests"] += 1
        b = int(r.get("bytes_out") or 0)
        e["bytes_out"] += b
        if r.get("method", "").upper() in ("POST", "PUT") and b >= p["large_upload_bytes"]:
            e["large_uploads"].append({"user": r["user"], "department": r["department"], "bytes": b, "at": r["timestamp"]})
        ts = r["timestamp"]
        e["first_seen"] = min(filter(None, [e["first_seen"], ts]))
        e["last_seen"] = max(filter(None, [e["last_seen"], ts]))

    if oauth_csv and Path(oauth_csv).exists():
        kw = [k.lower() for k in p["sensitive_oauth_scope_keywords"]]
        for g in _read(oauth_csv):
            svc = _match(g.get("app_domain", ""), catalog)
            if not svc:
                continue
            e = entry(svc)
            scopes = _split(g["scopes"].replace(" ", ";"))
            sensitive = [s for s in scopes if any(k in s.lower() for k in kw)]
            e["oauth_grants"].append({"user": g["user"], "department": g["department"], "app_name": g["app_name"],
                                      "scopes": scopes, "sensitive_scopes": sensitive, "granted_at": g["granted_at"]})
            e["users"].add(g["user"]); e["departments"][g["department"]].add(g["user"])

    out = []
    for e in agg.values():
        flags = []
        st = e["policy_status"]
        if st == "prohibited":
            flags.append(("critical", "Prohibited service in use"))
        elif st == "unreviewed":
            flags.append(("high", "Not reviewed or approved"))
        elif st == "restricted":
            flags.append(("medium", "Restricted service: confirm users are authorized"))
        sens = sorted(set(e["departments"]) & set(p["sensitive_departments"]))
        if sens and st != "approved":
            flags.append(("high", "Used by sensitive departments: " + ", ".join(sens)))
        if e["large_uploads"] and st != "approved":
            flags.append(("high", f"{len(e['large_uploads'])} large uploads (over {p['large_upload_bytes']:,} bytes)"))
        sg = [g for g in e["oauth_grants"] if g["sensitive_scopes"]]
        if sg:
            flags.append(("critical" if st != "approved" else "medium",
                          f"{len(sg)} OAuth grant(s) with mailbox/file/directory scopes"))
        sev = {"critical": 3, "high": 2, "medium": 1}
        e["flags"] = [{"severity": s, "detail": d} for s, d in sorted(flags, key=lambda x: -sev[x[0]])]
        e["risk"] = max((sev[s] for s, _ in flags), default=0)
        e["user_count"] = len(e["users"])
        e["departments"] = {k: len(v) for k, v in sorted(e["departments"].items())}
        e["users"] = sorted(e["users"])
        e["possible_data"] = sorted({p["department_data_hint"].get(d) for d in e["departments"]} - {None})
        out.append(e)
    out.sort(key=lambda x: (-x["risk"], -x["user_count"], -x["bytes_out"]))
    return out


# ====================================================================== blast radius
def blast_radius(vendors_csv, systems_csv, creds_csv, pol: dict, as_of: datetime, ai_services: list[dict] | None = None):
    p = pol["access"]
    W, PM, AM = p["data_class_weights"], p["privilege_multiplier"], p["access_method_multiplier"]
    systems = {s["system"]: {**s, "data_classes": _split(s["data_classes"])} for s in _read(systems_csv)}
    by_segment = defaultdict(list)
    for s in systems.values():
        by_segment[s.get("network_segment", "")].append(s["system"])
    creds_by = defaultdict(list)
    if creds_csv and Path(creds_csv).exists():
        for c in _read(creds_csv):
            creds_by[c["vendor_id"]].append(c)

    vendors = []
    for v in _read(vendors_csv):
        methods = _split(v["access_methods"])
        reach = set(_split(v["connected_systems"]))
        via_network = set()
        for seg in _split(v.get("network_segments", "")):
            via_network |= set(by_segment.get(seg, []))
        reach |= via_network
        data = set(_split(v["data_classes"]))
        for s in reach:
            data |= set(systems.get(s, {}).get("data_classes", []))
        priv = v.get("privilege", "read")
        creds = creds_by[v["vendor_id"]]
        if any(c.get("privilege") == "admin" for c in creds):
            priv = "admin"
        points = sum(W.get(d, 3) for d in data)
        score = round(points * PM.get(priv, 1) * max([AM.get(m, 1) for m in methods] or [1]), 1)

        flags = []
        stale = []
        for c in creds:
            lu = _d(c.get("last_used"))
            if not lu or (as_of.date() - lu).days > p["stale_credential_days"]:
                stale.append(c["credential_id"])
        if stale:
            flags.append(("high", f"{len(stale)} credential(s) unused for {p['stale_credential_days']}+ days: " + ", ".join(stale)))
        admin_creds = [c["credential_id"] for c in creds if c.get("privilege") == "admin"]
        if admin_creds:
            flags.append(("high", "Standing admin credential(s): " + ", ".join(admin_creds)))
        if not _yes(v.get("mfa_enforced", "")) and any(m in methods for m in ("vpn", "sso", "site_to_site")):
            flags.append(("high", "MFA not enforced on vendor's interactive access"))
        rv = _d(v.get("last_security_review"))
        if not rv:
            flags.append(("medium", "No security review on record"))
        elif (as_of.date() - rv).days > p["review_max_age_days"]:
            flags.append(("medium", f"Security review is {(as_of.date() - rv).days} days old"))
        if not _yes(v.get("breach_notice_clause", "")):
            flags.append(("medium", "No breach-notification clause in contract"))
        if via_network:
            flags.append(("high", f"Network-level access reaches {len(via_network)} system(s) beyond its stated integrations"))
        sev = {"critical": 3, "high": 2, "medium": 1}
        vendors.append({
            "vendor_id": v["vendor_id"], "vendor": v["vendor"], "service": v["service"], "owner": v.get("business_owner"),
            "kind": "contracted", "access_methods": methods, "privilege": priv,
            "systems": sorted(reach), "systems_via_network": sorted(via_network),
            "data_classes": sorted(data, key=lambda d: -W.get(d, 3)),
            "subprocessors": _split(v.get("subprocessors", "")),
            "credentials": len(creds), "score": score,
            "flags": [{"severity": s, "detail": d} for s, d in sorted(flags, key=lambda x: -sev[x[0]])],
        })

    # Fold unapproved AI services in as unvetted third parties.
    for a in ai_services or []:
        if a["policy_status"] == "approved":
            continue
        grants = a["oauth_grants"]
        reach = set()
        for g in grants:
            for s in g["sensitive_scopes"]:
                for key, system in p.get("scope_to_system", {}).items():
                    if key in s.lower() and system in systems:
                        reach.add(system)
        data = set()
        for s in reach:
            data |= set(systems.get(s, {}).get("data_classes", []))
        possible = set(a["possible_data"])
        # "Possible" data (inferred from who uses it) counts half, or full when large uploads were seen.
        pw = 1.0 if a["large_uploads"] else 0.5
        points = sum(W.get(d, 3) for d in data) + pw * sum(W.get(d, 3) for d in possible - data)
        method = "oauth" if grants else "file_transfer"
        priv = "read"
        score = round(points * PM[priv] * AM.get(method, 1), 1)
        vendors.append({
            "vendor_id": "AI:" + a["service_id"], "vendor": a["vendor"], "service": a["name"], "owner": None,
            "kind": "ai_" + a["policy_status"], "access_methods": [method], "privilege": priv,
            "systems": sorted(reach), "systems_via_network": [],
            "data_classes": sorted(data, key=lambda d: -W.get(d, 3)),
            "possible_data": sorted(possible - data, key=lambda d: -W.get(d, 3)),
            "subprocessors": [], "credentials": len(grants), "score": score,
            "users": a["user_count"],
            "flags": [{"severity": "critical" if a["policy_status"] == "prohibited" else "high",
                       "detail": (f"Restricted AI service: confirm the {a['user_count']} users are on the approved tier"
                                  if a["policy_status"] == "restricted" else
                                  f"AI service not approved (policy: {a['policy_status']}), {a['user_count']} users")}]
                     + [f for f in a["flags"] if not f["detail"].startswith(("Prohibited", "Not reviewed", "Restricted"))],
        })

    vendors.sort(key=lambda x: -x["score"])
    for i, v in enumerate(vendors, 1):
        v["rank"] = i

    concentration = []
    for name, s in systems.items():
        who = [v["service"] if v["kind"].startswith("ai_") else v["vendor"] for v in vendors if name in v["systems"]]
        concentration.append({"system": name, "criticality": int(s.get("criticality") or 3),
                              "data_classes": s["data_classes"], "vendor_count": len(who), "vendors": who})
    concentration.sort(key=lambda x: (-x["vendor_count"], -x["criticality"]))
    return vendors, concentration
