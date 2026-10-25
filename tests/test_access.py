"""Run with:  python -m pytest -q   (or  python tests/test_access.py)"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from mr_boddy import access  # noqa: E402

POL = json.loads((ROOT / "mr_boddy" / "policy.json").read_text())


def test_domain_matching_is_suffix_safe():
    cat = access.load_catalog()
    assert access._match("api2.cursor.sh", cat)["id"] == "cursor"
    assert access._match("notclaude.ai", cat) is None
    assert access._match("claude.ai", cat)["id"] == "anthropic-claude"


def test_userinfo_email_scope_is_not_mailbox():
    kw = [k.lower() for k in POL["access"]["sensitive_oauth_scope_keywords"]]
    assert not any(k in "userinfo.email" for k in kw)
    assert any(k in "mail.read" for k in kw)
    assert not any(k in "drive.file" for k in kw)


if __name__ == "__main__":
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            try:
                fn(); print("pass", name)
            except AssertionError:
                fails += 1; print("FAIL", name)
    sys.exit(fails)
