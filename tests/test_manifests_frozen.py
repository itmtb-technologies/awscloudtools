"""The capability contract is frozen (v1). Agents, the HTTP API and the generated agent
declaration are built from these manifests, and a hosted declaration is re-approved when they change.
So any change fails here until tests/manifests_v1.json is updated on purpose.

To change a manifest deliberately: regenerate the file with
  python -c "from test_manifests_frozen import dump; dump()"   (from tests/, PYTHONPATH=src)
and say in the commit why, and that the agent declaration needs re-approval.
Adding a check does not change this: required AWS actions are left out (additive)."""
import json
from pathlib import Path

from cloudtools.core.capability import all_capabilities, load_builtin

FILE = Path(__file__).with_name("manifests_v1.json")
KEYS = ("id", "kind", "permission", "input_schema", "read_only", "mutating", "requires_approval",
        "agent_visible", "hosted", "tier")


def current() -> dict:
    load_builtin()
    return {c.manifest.id: {k: getattr(c.manifest, k) for k in KEYS} for c in all_capabilities()}


def dump() -> None:
    FILE.write_text(json.dumps(current(), indent=1, sort_keys=True) + "\n", encoding="utf-8")


def test_manifests_match_the_frozen_contract():
    frozen = json.loads(FILE.read_text(encoding="utf-8"))
    now = json.loads(json.dumps(current(), sort_keys=True))
    added, removed = sorted(set(now) - set(frozen)), sorted(set(frozen) - set(now))
    changed = sorted(k for k in set(now) & set(frozen) if now[k] != frozen[k])
    assert not (added or removed or changed), (
        f"capability contract changed: added {added}, removed {removed}, changed {changed}. "
        "If deliberate, regenerate tests/manifests_v1.json (see the module docstring).")
