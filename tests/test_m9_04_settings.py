#!/usr/bin/env python3
"""Execute the settings controller guards; browser-chrome owns UI acceptance."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import SOURCE
OWNER = "browser/components/preferences/goodBearRussianPKI.js"


HARNESS = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const elements = new Map();
function element() {
  return {
    children: [], attributes: {}, listeners: {}, hidden: false, disabled: false,
    replaceChildren() { this.children = []; },
    append(child) { this.children.push(child); },
    setAttribute(key, value) { this.attributes[key] = value; },
    addEventListener(key, fn) { this.listeners[key] = fn; },
    focus() { this.focused = true; },
  };
}
const document = {
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, element());
    return elements.get(id);
  },
  createElementNS() { return element(); },
  l10n: {
    setAttributes(node, id, args) { node.l10n = { id, args }; },
    async formatValues(requests) { return requests.map(({ id }) => id); },
  },
};
const state = { enabled: true, locked: false, writeFails: false, answer: 1,
                prompts: 0, resetCalls: 0, resetFails: false, resetThrows: false,
                clearFails: false, calls: [] };
const origins = new Set(['https://one.example.test', 'https://two.example.test:8443']);
const history = new Set(origins);
const manager = {
  routingStateLoaded: true,
  async initialize() {},
  assignmentStore: {
    assignments() {
      return [...origins].map(origin => {
        const url = new URL(origin);
        return { scheme: 'https', host: url.hostname, port: Number(url.port || 443) };
      });
    },
  },
  trustHistoryStore: { entries() { return [...history]; } },
  async resetAssignment(origin) {
    state.resetCalls++;
    if (state.resetThrows) throw Error('storage failed');
    if (state.resetFails) return false;
    origins.delete(origin); history.delete(origin); return true;
  },
  async resetAllAssignments() {
    state.resetCalls++;
    if (state.resetThrows) throw Error('storage failed');
    if (state.resetFails) return false;
    origins.clear(); history.clear(); return true;
  },
};
const observers = new Map();
const Services = {
  prefs: {
    getBoolPref() { return state.enabled; },
    prefIsLocked() { return state.locked; },
    setBoolPref(key, value) {
      state.calls.push('pref');
      if (state.writeFails) throw Error('preference write failed');
      assert.ok(!state.locked);
      state.enabled = value;
      observers.get(key)?.observe(null, 'nsPref:changed', key);
    },
    addObserver(key, observer) { observers.set(key, observer); },
    removeObserver(key) { observers.delete(key); },
  },
  io: {
    newURI(value) {
      const url = new URL(value);
      return { asciiHost: url.hostname.replace(/^\[|\]$/g, ''),
        userPass: url.username + url.password, port: url.port ? Number(url.port) : -1,
        pathQueryRef: url.pathname + url.search + url.hash, prePath: url.origin };
    },
  },
  prompt: {
    BUTTON_POS_0: 1, BUTTON_POS_1: 256, BUTTON_TITLE_IS_STRING: 127,
    BUTTON_TITLE_CANCEL: 2, BUTTON_POS_1_DEFAULT: 16777216, MODAL_TYPE_CONTENT: 3,
    async asyncConfirmEx(context, modalType, title, message, flags) {
      state.prompts++;
      assert.equal(modalType, this.MODAL_TYPE_CONTENT);
      assert.ok(flags & this.BUTTON_POS_1_DEFAULT);
      return { getProperty(key) { assert.equal(key, 'buttonNumClicked'); return state.answer; } };
    },
  },
};
const context = vm.createContext({ document, Services, console: { error() {} },
  Cc: { '@mozilla.org/psm;1': { getService() { return {
    clearGoodBearRussianPKIContainerId() {
      state.calls.push('clear');
      if (state.clearFails) throw Error('scope revocation failed');
    },
  }; } } },
  Ci: { nsINSSComponent: {} },
  window: { browsingContext: {}, addEventListener() {} },
  ChromeUtils: { importESModule() { return { GoodBearRussianPKIContainer: manager }; } },
});
vm.runInContext(input.source, context);
const pane = context.gGoodBearRussianPKIPane;
(async () => {
  pane.init();
  await pane.ready;
  await eval(`(async () => { ${input.body} })()`);
})().catch(error => { console.error(error); process.exitCode = 1; });
"""


class SettingsControllerTest(unittest.TestCase):
    def run_controller(self, body: str) -> None:
        result = subprocess.run(["node", "-e", HARNESS], input=json.dumps({
            "source": (SOURCE / OWNER).read_text(encoding="utf-8"), "body": body,
        }), text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_live_preference_lock_and_failed_write_do_not_advertise_a_change(self) -> None:
        self.run_controller("""
          const checkbox = elements.get('goodBearRussianPKIEnabled');
          assert.equal(checkbox.checked, true);
          checkbox.checked = false; pane._setEnabled();
          assert.equal(state.enabled, false); assert.equal(checkbox.checked, false);
          Services.prefs.setBoolPref(pane._enabledPref, true);
          assert.equal(checkbox.checked, true);
          for (const denied of ['locked', 'writeFails']) {
            state[denied] = true; checkbox.checked = false; pane._setEnabled();
            assert.equal(state.enabled, true); assert.equal(checkbox.checked, true);
            if (denied === 'writeFails') {
              assert.equal(elements.get('goodBearRussianPKIError').l10n.id,
                           'goodbear-russian-pki-settings-enable-failed');
            }
            state[denied] = false;
          }
        """)

    def test_only_canonical_https_origin_rows_can_be_reset(self) -> None:
        self.run_controller("""
          assert.equal(pane._origin({ scheme: 'https', host: '::1', port: 8443 }), 'https://[::1]:8443');
          for (const host of ['user@one.example.test', 'one.example.test/path?secret', '<script>']) {
            assert.equal(pane._origin({ scheme: 'https', host, port: 443 }), null);
          }
          for (const origin of ['http://one.example.test', 'https://one.example.test/path?secret', 'https://unknown.example.test']) {
            assert.equal(await pane.reset(origin), false);
          }
          assert.equal(state.prompts, 0); assert.equal(state.resetCalls, 0);
          const button = elements.get('goodBearRussianPKISites').children[0].children[0];
          assert.equal(button.l10n.args.origin, 'https://one.example.test');
        """)

    def test_disable_revokes_native_scope_before_preference_observers(self) -> None:
        self.run_controller("""
          const checkbox = elements.get('goodBearRussianPKIEnabled');
          checkbox.checked = false; pane._setEnabled();
          assert.deepEqual(state.calls, ['clear', 'pref']);
          assert.equal(state.enabled, false);
          state.calls = [];
          checkbox.checked = true; pane._setEnabled();
          assert.deepEqual(state.calls, ['pref']);
          state.calls = []; state.clearFails = true;
          checkbox.checked = false; pane._setEnabled();
          assert.deepEqual(state.calls, ['clear']);
          assert.equal(state.enabled, true);
          assert.equal(checkbox.checked, true);
          assert.equal(elements.get('goodBearRussianPKIError').l10n.id,
                       'goodbear-russian-pki-settings-enable-failed');
        """)

    def test_single_and_all_reset_require_affirmative_confirmation(self) -> None:
        self.run_controller("""
          assert.equal(await pane.reset('https://one.example.test'), false);
          assert.equal(await pane.reset(), false);
          assert.equal(origins.size, 2); assert.equal(history.size, 2);
          assert.equal(state.resetCalls, 0);
          state.answer = 0;
          assert.equal(await pane.reset('https://one.example.test'), true);
          assert.equal(origins.size, 1); assert.equal(history.size, 1);
          assert.equal(await pane.reset(), true);
          assert.equal(origins.size, 0); assert.equal(history.size, 0);
          assert.equal(elements.get('goodBearRussianPKIEmpty').hidden, false);
        """)

    def test_pending_prompt_and_closed_pane_cannot_mutate(self) -> None:
        self.run_controller("""
          let finish, opened;
          const shown = new Promise(resolve => { opened = resolve; });
          Services.prompt.asyncConfirmEx = () => new Promise(resolve => { finish = resolve; opened(); });
          const pending = pane.reset();
          await shown;
          assert.ok(finish); assert.equal(await pane.reset(), false);
          pane._alive = false;
          finish({ getProperty() { return 0; } });
          assert.equal(await pending, false); assert.equal(state.resetCalls, 0);
          assert.equal(origins.size, 2);
        """)

    def test_failed_reset_and_missing_confirmation_keep_the_list(self) -> None:
        self.run_controller("""
          state.answer = 0;
          for (const failure of ['resetFails', 'resetThrows']) {
            state[failure] = true;
            assert.equal(await pane.reset(), false);
            assert.equal(origins.size, 2); assert.equal(history.size, 2);
            assert.equal(elements.get('goodBearRussianPKIError').hidden, false);
            assert.equal(elements.get('goodBearRussianPKISites').children.length, 2);
            state[failure] = false;
          }
          const calls = state.resetCalls, prompts = state.prompts;
          document.l10n.formatValues = async () => ['', '', ''];
          assert.equal(await pane.reset(), false);
          assert.equal(state.resetCalls, calls); assert.equal(state.prompts, prompts);
        """)


if __name__ == "__main__":
    unittest.main()
