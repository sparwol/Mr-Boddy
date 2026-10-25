# Mr. Boddy

*Named for Mr. Boddy from the 1985 film Clue, the man who knows every guest's secrets. This one knows what every outside party in your house can reach, including the ones nobody invited.*

Third-party blast radius mapping plus shadow AI discovery, for an enterprise security team. Standard-library Python only (3.10+).

It answers one question: which outside services can reach our data, how much damage each could do if breached, and did we approve them? Unapproved AI services found in traffic are ranked on the same scale as contracted vendors.

## Quick start

```bash
python sample/generate.py
python -m mr_boddy.cli access --data sample_data --out out
python tests/test_access.py
```

Outputs in `out/`:
- `access_report.json`: ranked parties with reach and issues, shared systems, AI service usage
- `dashboard/*.json`: row files for the dashboard in `dashboard/index.html`

## Input files (CSV)

- `systems.csv`: system, data_classes (semicolon list), criticality, network_segment
- `vendors.csv`: vendor_id, vendor, service, business_owner, data_classes, access_methods (sso, oauth, api_key, vpn, site_to_site, service_account, on_prem_agent, file_transfer), privilege (read, write, admin), connected_systems, network_segments, mfa_enforced, last_security_review, breach_notice_clause, subprocessors
- `vendor_credentials.csv`: vendor_id, credential_id, type, privilege, created, last_used, owner
- `proxy_logs.csv`: timestamp, user, department, dest_host, method, bytes_out, bytes_in, from your secure web gateway or proxy
- `oauth_grants.csv`: user, department, app_name, app_domain, scopes (space separated), granted_at, from Entra ID or Google Workspace OAuth app reports
- `ai_policy.csv`: service_id, status (approved, restricted, prohibited; anything unlisted is "unreviewed"), notes

## Blast radius score

Score = (sum of data-type weights for everything the party can reach) x (privilege multiplier) x (riskiest connection multiplier).

Reach includes systems in network segments a party gets by VPN or site-to-site link, which often goes well beyond its stated integration. For AI services, reach comes only from OAuth scopes users granted: mail and calendar scopes reach email, file and site scopes reach file storage. Logins that only share an email address (`userinfo.email`) and Google's per-file `drive.file` scope are not counted as mailbox or file access. Data a department might have pasted in is labeled "possible" and counts half, or in full when large uploads were seen.

The score ranks parties against each other. It is not an absolute risk measure.

Issues flagged per party: stale credentials (default 90 days), standing admin credentials, no MFA on interactive access, old or missing security review (default 365 days), no breach-notification clause, network access beyond stated integrations.

## Policy

Weights and limits live in `mr_boddy/policy.json`; AI service domains in `mr_boddy/ai_catalog.json`. Both are starting points to edit for your environment, not industry standards.

## Limits

- Shadow AI detection sees only what passes through your proxy and identity provider. Personal devices off-network are invisible to it.
- Sample data: the company, users, vendors (fictional names) and logs are invented. AI services are matched by their real public domains; their policy status is the fictional company's choice.
