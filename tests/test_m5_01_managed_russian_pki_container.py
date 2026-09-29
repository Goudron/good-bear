#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASELINE = json.loads(
    (ROOT / "config/firefox-baseline.json").read_text(encoding="utf-8")
)
FIREFOX = ROOT / "source" / "worktrees" / f"firefox-{BASELINE['version']}"
CONTRACT = json.loads(
    (ROOT / "config/m5-01-managed-russian-pki-container-contract.json").read_text(
        encoding="utf-8"
    )
)


def read_firefox(relative: str) -> str:
    return (FIREFOX / relative).read_text(encoding="utf-8")


class M501ManagedRussianPKIContainerTest(unittest.TestCase):
    def test_patch_is_pinned_after_m4_and_carries_the_exact_purpose(self) -> None:
        self.assertEqual(CONTRACT["task"], "GB100-M5-01")
        self.assertEqual(CONTRACT["firefox_version"], BASELINE["version"])
        series = [
            line
            for line in (ROOT / "patches/series").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        patch = Path(CONTRACT["patch"])
        self.assertEqual(series.index(patch.name), 7)
        self.assertEqual(series[6], "0007-good-bear-trust-results-performance.patch")
        self.assertEqual(series.count(patch.name), 1)
        patch_text = (ROOT / patch).read_text(encoding="utf-8")
        for required in (
            "GOOD_BEAR_RUSSIAN_PKI_CONTAINER_PURPOSE",
            CONTRACT["purpose"],
            "createManagedIdentity",
            "contextual-identity-deleted",
            "GoodBearRussianPKIContainer.start()",
        ):
            self.assertIn(required, patch_text)

    def test_manager_is_native_id_authority_and_ambiguous_state_fails_closed(self) -> None:
        manager = read_firefox(CONTRACT["manager_owner"])
        for required in (
            "ContextualIdentityService",
            "managedPurpose",
            "getPublicIdentities()",
            "createManagedIdentity(",
            "identity.userContextId > 0",
            "matches.length > 1",
            "this._dedicatedUserContextId = null",
            "getScopeSnapshot()",
            "contextual-identity-deleted",
        ):
            self.assertIn(required, manager)
        ensure = manager.split("ensureContainer() {", 1)[1].split(
            "\n  _repairPresentation", 1
        )[0]
        self.assertLess(
            ensure.index("matches.length > 1"), ensure.index("matches.length === 1")
        )
        self.assertNotIn("identity.name ===", ensure)
        self.assertNotIn("identity.color ===", ensure)
        self.assertNotIn("identity.icon ===", ensure)
        for forbidden in ("window.open", "DEFAULT_USER_CONTEXT_ID"):
            self.assertNotIn(forbidden, manager)

    def test_native_service_persists_managed_purpose_and_startup_runs_after_load(self) -> None:
        identity = read_firefox(CONTRACT["identity_owner"])
        self.assertIn("createManagedIdentity(name, icon, color, purpose)", identity)
        self.assertIn("identity.managedPurpose = managedPurpose", identity)
        startup = read_firefox(CONTRACT["startup_owner"])
        load = startup.split('name: "ContextualIdentityService.load"', 1)[1].split(
            "lazy.Discovery.update();", 1
        )[0]
        self.assertLess(
            load.index("await lazy.ContextualIdentityService.load()"),
            load.index("await lazy.GoodBearRussianPKIContainer.initialize()"),
        )

    def test_browser_test_covers_real_origin_attributes_repair_and_stale_id(self) -> None:
        test = read_firefox(CONTRACT["test_owner"])
        for required in (
            "createNewInstanceForTesting",
            "GoodBearRussianPKIContainerManager",
            "BrowserTestUtils.addTab",
            "browser.contentPrincipal.userContextId",
            "identityService.remove(container.userContextId)",
            "isnot(",
            "stale ID no longer names a container",
            "ambiguous purpose is not selected",
        ):
            self.assertIn(required, test)
        self.assertNotIn("openTabInUserContext(", test)
        self.assertNotIn("equal(", test)


if __name__ == "__main__":
    unittest.main()
