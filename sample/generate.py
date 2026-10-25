"""Generate a SAMPLE dataset for a fictional company, "Halvorsen Freight".

Everything here is invented: the company, users, vendors (fictional names), logs.
AI services are matched by their real public domains.
"""
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "sample_data"
AS_OF = datetime(2026, 10, 25, 9, 0)
R = random.Random(20261025)
def write(name, rows, cols=None):
    OUT.mkdir(exist_ok=True)
    cols = cols or list(rows[0].keys())
    with open(OUT / name, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    print(f"{name:<24} {len(rows):>6} rows")


BUS = ["Operations", "Finance", "HR", "Engineering", "Sales", "Support", "Legal", "Marketing", "Security", "IT"]

# ------------------------------------------------------------------ systems & vendors (fictional vendors)
systems = [
    ("Email (Microsoft 365)", "PII;customer_data;credentials;internal", 5, "cloud"),
    ("File storage (SharePoint/OneDrive)", "PII;financial;employee_data;internal;customer_data", 5, "cloud"),
    ("ERP (Oracle EBS)", "financial;PII;customer_data", 5, "dc-core"),
    ("Active Directory", "credentials;employee_data", 5, "dc-core"),
    ("Backup vault", "credentials;financial;PII;employee_data;customer_data", 5, "dc-core"),
    ("HRIS", "employee_data;PII;financial", 4, "cloud"),
    ("CRM", "customer_data;PII", 4, "cloud"),
    ("Payments gateway", "PCI;financial", 5, "dmz"),
    ("Source control", "source_code;credentials", 4, "cloud"),
    ("Data warehouse", "customer_data;financial;PII", 4, "dc-apps"),
    ("Customer portal", "customer_data;PII", 4, "dmz"),
    ("Warehouse management", "customer_data;internal", 4, "facilities"),
    ("Building management (HVAC)", "internal", 2, "facilities"),
    ("Fleet telematics", "customer_data;internal", 3, "dc-apps"),
    ("IT ticketing", "internal;PII", 3, "cloud"),
]
write("systems.csv", [dict(system=s, data_classes=d, criticality=c, network_segment=g) for s, d, c, g in systems])

V = [
    # id, vendor, service, owner, data, methods, priv, systems, segments, mfa, review, notice, subprocessors
    ("V01", "Corvid Managed IT", "Managed service provider (24x7 ops)", "CIO", "credentials", "vpn;service_account;on_prem_agent", "admin",
     "Active Directory;Backup vault;IT ticketing", "dc-core;dc-apps", "no", "2025-02-10", "yes", "Remote support tool vendor;Offshore NOC subcontractor"),
    ("V02", "Ledgerline", "Payroll SaaS", "CFO", "employee_data;PII;financial", "sso;api_key", "write",
     "HRIS", "", "yes", "2026-05-04", "yes", "Cloud hosting provider;Payment processor"),
    ("V03", "Northgate Analytics", "BI / reporting contractor", "VP Data", "customer_data", "vpn;service_account", "read",
     "Data warehouse", "dc-apps", "no", "", "no", "Freelance analysts"),
    ("V04", "Tidewater HVAC Services", "Building HVAC maintenance", "Facilities", "internal", "site_to_site", "admin",
     "Building management (HVAC)", "facilities", "no", "2023-08-19", "no", ""),
    ("V05", "Brightpath CRM", "CRM SaaS", "VP Sales", "customer_data;PII", "sso;oauth;api_key", "write",
     "CRM;Email (Microsoft 365)", "", "yes", "2026-01-22", "yes", "Cloud hosting provider;Email delivery service;Support desk vendor"),
    ("V06", "Keystone Pay", "Card payment processing", "CFO", "PCI;financial", "api_key", "write",
     "Payments gateway", "", "yes", "2026-08-30", "yes", "Card networks;Fraud scoring vendor"),
    ("V07", "Quillstack", "E-signature SaaS", "General Counsel", "PII;customer_data", "sso;oauth", "read",
     "File storage (SharePoint/OneDrive)", "", "yes", "2025-12-01", "yes", "Cloud hosting provider"),
    ("V08", "Ironbark Backup", "Offsite backup / DR", "CIO", "credentials", "service_account;on_prem_agent", "admin",
     "Backup vault", "dc-core", "yes", "2026-03-15", "yes", "Object storage provider"),
    ("V09", "Pinecrest CI", "CI/CD build service", "VP Engineering", "source_code", "oauth;api_key", "write",
     "Source control", "", "yes", "2025-06-11", "yes", "Cloud hosting provider;Build cache CDN"),
    ("V10", "Harborline Telematics", "Fleet GPS / telematics", "COO", "customer_data", "api_key;vpn", "write",
     "Fleet telematics", "dc-apps", "no", "2024-10-02", "yes", "Cellular carrier"),
    ("V11", "Saltmarsh Legal eDiscovery", "eDiscovery / litigation hold", "General Counsel", "PII;employee_data", "oauth", "read",
     "Email (Microsoft 365);File storage (SharePoint/OneDrive)", "", "yes", "2026-02-27", "yes", "Review contractors"),
    ("V12", "Fernhill Recruiting", "Applicant tracking SaaS", "CHRO", "PII;employee_data", "sso", "write",
     "HRIS", "", "no", "", "no", "Background check provider"),
    ("V13", "Granite Helpdesk", "IT ticketing SaaS", "CIO", "internal;PII", "sso;api_key", "write",
     "IT ticketing;Active Directory", "", "yes", "2026-06-18", "yes", "Cloud hosting provider"),
    ("V14", "Ospreyware WMS", "Warehouse management vendor support", "COO", "customer_data", "vpn", "admin",
     "Warehouse management", "facilities", "no", "2025-04-09", "yes", ""),
]
write("vendors.csv", [dict(vendor_id=a, vendor=b, service=c, business_owner=d, data_classes=e, access_methods=f, privilege=g,
                           connected_systems=h, network_segments=i, mfa_enforced=j, last_security_review=k,
                           breach_notice_clause=l, subprocessors=m) for a, b, c, d, e, f, g, h, i, j, k, l, m in V])

creds = []
for vid, *_ in V:
    for j in range(R.randint(1, 4)):
        used = AS_OF - timedelta(days=R.choice([1, 2, 5, 12, 30, 45, 120, 260, 400]))
        priv = R.choice(["read", "write", "write", "admin"]) if vid in ("V01", "V08", "V04", "V14") else R.choice(["read", "write"])
        creds.append(dict(vendor_id=vid, credential_id=f"{vid}-cred-{j + 1}",
                          type=R.choice(["service_account", "api_key", "oauth_app", "vpn_account"]),
                          privilege=priv, created=(used - timedelta(days=R.randint(30, 700))).date().isoformat(),
                          last_used="" if R.random() < .05 else used.date().isoformat(),
                          owner=f"{vid.lower()}-contact@vendor.example"))
write("vendor_credentials.csv", creds)

# ------------------------------------------------------------------ proxy logs + OAuth grants
users = [(f"u{k:04d}", R.choice(BUS)) for k in range(1, 321)]
AI_USE = [
    # host, dept weights, share of users, post-heavy?, big uploads?
    ("copilot.microsoft.com", None, .35, False, False),
    ("chatgpt.com", None, .22, True, True),
    ("gemini.google.com", None, .08, False, False),
    ("chat.deepseek.com", {"Engineering": 4, "Finance": 1}, .03, True, True),
    ("otter.ai", {"Legal": 3, "HR": 3, "Sales": 1}, .05, True, True),
    ("app.fireflies.ai", {"Sales": 4, "Support": 2}, .04, True, False),
    ("www.perplexity.ai", None, .06, False, False),
    ("api2.cursor.sh", {"Engineering": 1}, .5, True, True),
    ("huggingface.co", {"Engineering": 1}, .4, False, False),
    ("character.ai", {"Support": 1}, .01, False, False),
    ("gamma.app", {"Marketing": 3, "Sales": 1}, .15, True, True),
    ("openrouter.ai", {"Engineering": 1}, .12, True, False),
    ("claude.ai", None, .07, True, False),
]
OTHER = ["outlook.office365.com", "teams.microsoft.com", "github.com", "zoom.us", "slack.com", "intranet.halvorsen.example"]
logs = []
start = AS_OF - timedelta(days=14)
for host, depts, share, post_heavy, big in AI_USE:
    pool = [u for u in users if not depts or u[1] in depts]
    chosen = R.sample(pool, max(1, int(len(pool) * share)))
    for u, d in chosen:
        for _ in range(R.randint(3, 40)):
            ts = start + timedelta(seconds=R.randint(0, 14 * 86400))
            method = "POST" if post_heavy and R.random() < .6 else R.choice(["GET", "GET", "POST"])
            b = R.randint(2_000, 60_000)
            if big and method == "POST" and R.random() < .06:
                b = R.randint(1_200_000, 25_000_000)
            logs.append(dict(timestamp=ts.isoformat(timespec="seconds"), user=u, department=d, dest_host=host,
                             method=method, bytes_out=b, bytes_in=R.randint(5_000, 400_000)))
for _ in range(9000):
    u, d = R.choice(users)
    ts = start + timedelta(seconds=R.randint(0, 14 * 86400))
    logs.append(dict(timestamp=ts.isoformat(timespec="seconds"), user=u, department=d, dest_host=R.choice(OTHER),
                     method=R.choice(["GET", "GET", "POST"]), bytes_out=R.randint(500, 80_000), bytes_in=R.randint(1_000, 900_000)))
logs.sort(key=lambda r: r["timestamp"])
write("proxy_logs.csv", logs)

grants = []
for u, d in R.sample([x for x in users if x[1] in ("Sales", "Support", "Legal")], 16):
    grants.append(dict(user=u, department=d, app_name="Fireflies.ai Notetaker", app_domain="fireflies.ai",
                       scopes="Calendars.Read Mail.Read offline_access User.Read", granted_at=(AS_OF - timedelta(days=R.randint(1, 200))).date().isoformat()))
for u, d in R.sample([x for x in users if x[1] in ("Legal", "HR")], 6):
    grants.append(dict(user=u, department=d, app_name="Otter.ai", app_domain="otter.ai",
                       scopes="Calendars.Read User.Read", granted_at=(AS_OF - timedelta(days=R.randint(1, 200))).date().isoformat()))
for u, d in R.sample([x for x in users if x[1] == "Finance"], 5):
    grants.append(dict(user=u, department=d, app_name="ChatGPT connector", app_domain="chatgpt.com",
                       scopes="Files.Read.All Sites.Read.All offline_access", granted_at=(AS_OF - timedelta(days=R.randint(1, 90))).date().isoformat()))
for u, d in R.sample([x for x in users if x[1] == "Marketing"], 4):
    grants.append(dict(user=u, department=d, app_name="Gamma", app_domain="gamma.app",
                       scopes="drive.file userinfo.email", granted_at=(AS_OF - timedelta(days=R.randint(1, 90))).date().isoformat()))
write("oauth_grants.csv", grants)

write("ai_policy.csv", [
    dict(service_id="ms-copilot", status="approved", notes="Enterprise tenant with data protection"),
    dict(service_id="openai-chatgpt", status="restricted", notes="Enterprise workspace only; personal accounts not allowed"),
    dict(service_id="huggingface", status="restricted", notes="Model downloads OK; no uploads of company data"),
    dict(service_id="deepseek-chat", status="prohibited", notes="Blocked by policy"),
    dict(service_id="character-ai", status="prohibited", notes="Not for business use"),
])
print("as_of:", AS_OF.isoformat())
