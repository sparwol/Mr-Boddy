"""Flatten reports into row files the dashboards read (one JSON array of rows per dataset)."""
from __future__ import annotations

import json
from pathlib import Path

SEV = {"critical": 3, "high": 2, "medium": 1}


def _dump(path: Path, rows):
    path.write_text(json.dumps(rows, indent=0, default=str))


def access(report: dict, out: Path):
    out.mkdir(parents=True, exist_ok=True)
    vendors = []
    for v in report["vendors"]:
        fl = v["flags"]
        vendors.append({
            "vendor_id": v["vendor_id"], "rank": v["rank"], "vendor": v["vendor"], "service": v["service"],
            "kind": v["kind"], "score": v["score"], "privilege": v["privilege"],
            "access_methods": ", ".join(v["access_methods"]), "system_count": len(v["systems"]),
            "systems": ", ".join(v["systems"]), "via_network": ", ".join(v["systems_via_network"]),
            "data_classes": ", ".join(v["data_classes"]), "possible_data": ", ".join(v.get("possible_data") or []),
            "subprocessor_count": len(v["subprocessors"]), "subprocessors": ", ".join(v["subprocessors"]),
            "credentials": v["credentials"], "users": v.get("users"),
            "worst_flag": max((f["severity"] for f in fl), key=lambda s: SEV[s], default="none"),
            "flag_count": len(fl), "flags": fl, "systems_list": v["systems"],
        })
    _dump(out / "ac_vendors.json", vendors)
    _dump(out / "ac_concentration.json", [
        {"system": c["system"], "criticality": c["criticality"], "data_classes": ", ".join(c["data_classes"]),
         "vendor_count": c["vendor_count"], "vendors": ", ".join(c["vendors"])} for c in report["concentration"]])
    ai = []
    for s in report["shadow_ai"]:
        ai.append({
            "service_id": s["service_id"], "service": s["name"], "vendor": s["vendor"], "category": s["category"],
            "policy_status": s["policy_status"], "policy_notes": s["policy_notes"], "users": s["user_count"],
            "requests": s["requests"], "bytes_out": s["bytes_out"], "large_uploads": len(s["large_uploads"]),
            "oauth_grants": len(s["oauth_grants"]),
            "sensitive_grants": sum(bool(g["sensitive_scopes"]) for g in s["oauth_grants"]),
            "risk": {3: "critical", 2: "high", 1: "medium"}.get(s["risk"], "none"),
            "departments": s["departments"], "possible_data": ", ".join(s["possible_data"]),
            "flags": s["flags"], "first_seen": s["first_seen"] or "", "last_seen": s["last_seen"] or "",
        })
    _dump(out / "ac_shadow_ai.json", ai)
    _dump(out / "ac_meta.json", [{"as_of": report["as_of"], **{k: report["policy"][k] for k in (
        "stale_credential_days", "review_max_age_days", "large_upload_bytes", "data_class_weights",
        "privilege_multiplier", "access_method_multiplier")}}])
