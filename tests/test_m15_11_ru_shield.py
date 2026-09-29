#!/usr/bin/env python3
"""Execute the actual badge controller and guard inherited Firefox shield owners.

These owner checks deliberately do not claim localized binary or screen-reader
acceptance. The M15-11 visual/manual gate remains pending until that evidence exists.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import SOURCE
import verify_m15_11_upstream_ui_watch as WATCH


CONTROLLER_PROBE = r"""
const fs = require("node:fs");
const vm = require("node:vm");
const assert = require("node:assert/strict");
const nodes = new Map();
function node(id) {
  if (!nodes.has(id)) nodes.set(id, {
    hidden: true, collapsed: false, attributes: new Map(),
    classList: { add() {} },
    setAttribute(name, value) { this.attributes.set(name, value); },
    removeAttribute(name) { this.attributes.delete(name); },
    getAttribute(name) { return this.attributes.get(name) || null; },
  });
  return nodes.get(id);
}
const shield = node("trust-icon-container");
shield.setAttribute("aria-label", "Сведения о сайте; заблокировано 3 трекера");
const badge = node("trust-goodbear-russian-pki-label");
badge.parentElement = shield;
const context = {
  ChromeUtils: { defineESModuleGetters() {} },
  Ci: {
    nsITransportSecurityInfo: { Invalid: 0, Standard: 1, RussianPKI: 2 },
    nsIWebProgressListener: { STATE_IS_SECURE: 1, STATE_IS_BROKEN: 2 },
  },
  document: {
    getElementById: node,
    l10n: { setAttributes(element, id) { element.setAttribute("data-l10n-id", id); } },
  },
  gNavigatorBundle: { getString: id => id, getFormattedString: id => id },
  gBrowser: { selectedBrowser: { documentURI: { scheme: "https" } } },
  UrlbarPrefs: { getScotchBonnetPref() { return false; } },
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(process.argv[1], "utf8"), context);
const handler = context.gIdentityHandler;
for (const [key, value] of Object.entries({
  _insecureConnectionTextEnabled: true,
  _isURILoadedFromFile: false,
  _uriHasHost: true,
  getIdentityData() { return { caOrg: "Russian Trusted Root CA" }; },
})) Object.defineProperty(handler, key, { value, writable: true, configurable: true });

const cases = [
  ["native Russian PKI", { goodBearTrustDomain: 2 }, 1, true],
  ["standard chain in the same container", { goodBearTrustDomain: 1 }, 1, false],
  ["Russian PKI returns", { goodBearTrustDomain: 2 }, 1, true],
  ["invalid chain", { goodBearTrustDomain: 0 }, 0, false],
  ["unknown native domain", { goodBearTrustDomain: 99 }, 1, false],
  ["issuer name alone", {}, 1, false],
  ["broken connection with stale Russian metadata", { goodBearTrustDomain: 2 }, 2, false],
  ["missing security metadata", null, 1, false],
];
for (const [label, securityInfo, state, expected] of cases) {
  handler._secInfo = securityInfo;
  handler._state = state;
  handler._refreshIdentityIcons();
  assert.equal(!badge.hidden, expected, `${label}: visible RU`);
  assert.equal(shield.getAttribute("aria-describedby"), expected ?
    "trust-goodbear-russian-pki-description" : null, `${label}: description`);
  assert.equal(badge.getAttribute("data-l10n-id"), expected ?
    "identity-goodbear-russian-pki-label" : null, `${label}: Russian localization`);
  assert.equal(shield.getAttribute("aria-label"),
    "Сведения о сайте; заблокировано 3 трекера", `${label}: native accessible name`);
}
console.log(JSON.stringify({ cases: cases.length, passed: true }));
"""


class RussianShieldOwnerTest(unittest.TestCase):
    def audit(self) -> dict:
        return json.loads(WATCH.CONTRACT.read_text(encoding="utf-8"))["transitions"][0]["ru_shield_source_audit"]

    def test_upstream_artwork_and_style_remain_exact(self) -> None:
        WATCH.verify_ru_shield_source(SOURCE, self.audit())

    def test_changed_upstream_shield_is_rejected(self) -> None:
        audit = self.audit()
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            for owner in audit["unchanged_owner_sha256"]:
                path = fixture / owner
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(SOURCE / owner, path)
            icon = fixture / "browser/themes/shared/identity-block/trust-icon-active.svg"
            icon.write_bytes(icon.read_bytes().replace(b'width="16"', b'width="20"'))
            with self.assertRaisesRegex(WATCH.WatchError, "owner changed without review"):
                WATCH.verify_ru_shield_source(fixture, audit)

    def test_native_ru_state_and_accessible_description_clear_together(self) -> None:
        completed = subprocess.run(
            ["node", "-e", CONTROLLER_PROBE, str(SOURCE / "browser/base/content/browser-siteIdentity.js")],
            check=True, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(json.loads(completed.stdout), {"cases": 8, "passed": True})

    def test_description_reuses_localized_connection_copy_without_visible_geometry(self) -> None:
        markup = (SOURCE / "browser/base/content/navigator-toolbox.inc.xhtml").read_text(encoding="utf-8")
        description = markup.split('id="trust-goodbear-russian-pki-description"', 1)[1].split("/>", 1)[0]
        self.assertIn('data-l10n-id="identity-goodbear-russian-pki-connection"', description)
        self.assertIn('hidden="true"', description)


if __name__ == "__main__":
    unittest.main()
