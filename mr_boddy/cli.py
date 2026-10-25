"""Mr. Boddy CLI.

  python -m mr_boddy.cli access   --data sample_data/ --out out/
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from . import access, export

HERE = Path(__file__).parent


def _policy(path):
    return json.loads(Path(path or HERE / "policy.json").read_text())


def _as_of(v):
    return datetime.fromisoformat(v) if v else datetime.now().replace(microsecond=0)


def cmd_access(a):
    pol, as_of = _policy(a.policy), _as_of(a.as_of)
    d, out = Path(a.data), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    ai = access.shadow_ai(d / "proxy_logs.csv", d / "oauth_grants.csv", d / "ai_policy.csv", pol)
    vendors, conc = access.blast_radius(d / "vendors.csv", d / "systems.csv", d / "vendor_credentials.csv", pol, as_of, ai)
    report = {"generated": datetime.now().isoformat(timespec="seconds"), "as_of": as_of.isoformat(),
              "policy": pol["access"], "vendors": vendors, "concentration": conc, "shadow_ai": ai}
    (out / "access_report.json").write_text(json.dumps(report, indent=1, default=str))
    export.access(json.loads(json.dumps(report, default=str)), out / "dashboard")
    print(f"Vendors ranked: {len(vendors)} ({sum(v['kind'].startswith('ai_') for v in vendors)} AI services not fully approved)")
    print(f"AI services seen: {len(ai)}  unapproved: {sum(x['policy_status']!='approved' for x in ai)}")
    print("->", out / "access_report.json")


def main():
    ap = argparse.ArgumentParser(prog="mr_boddy")
    sub = ap.add_subparsers(required=True)
    for name, fn in (("access", cmd_access),):
        p = sub.add_parser(name)
        p.add_argument("--data", required=True); p.add_argument("--out", default="out")
        p.add_argument("--policy"); p.add_argument("--as-of", dest="as_of")
        p.set_defaults(fn=fn)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
