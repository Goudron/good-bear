#!/usr/bin/env python3
"""Execute real UI methods with adversarial data; not native TLS/runtime proof."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import SOURCE, TOOLCHAIN

NODE = TOOLCHAIN / "node/bin/node"


HARNESS = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
const Ci = { nsITransportSecurityInfo: { Invalid: 0, Standard: 1, RussianPKI: 2 },
  nsIWebProgressListener: { STATE_IS_SECURE: 1, STATE_CERT_USER_OVERRIDDEN: 2 } };
const fields = new Map();
function node() { return { hidden: false, disabled: false, textContent: '', attrs: {},
  classList: new Set(),
  removeAttribute(name) { delete this.attrs[name]; },
  setAttribute(name, value) { this.attrs[name] = value; },
  getAttribute(name) { return this.attrs[name]; },
}; }
const document = {
  getElementById(id) { if (!fields.has(id)) fields.set(id, node()); return fields.get(id); },
  l10n: { setAttributes(element, id) { element.attrs['data-l10n-id'] = id; } },
};
function makeBrowser() {
  const leaf = { subjectName: '<script>untrusted subject</script>', issuerName: 'Actual issuer',
    equals(other) { return other === this; }, getBase64DERString() { return 'YWJj+/='; } };
  const root = { subjectName: 'Actual root', sha256Fingerprint: Array(32).fill('AB').join(':'),
    getBase64DERString() { return 'cm9vdA=='; } };
  const secInfo = { goodBearTrustDomain: 2, errorCode: 0, serverCert: leaf,
    succeededCertChain: [leaf, root] };
  Object.defineProperty(secInfo, 'handshakeCertificates', {
    get() { throw Error('Unverified certificate path must never be read'); } });
  return { securityUI: { state: 1, secInfo },
    currentURI: { schemeIs(scheme) { return scheme === 'https'; }, displayHost: 'site.example',
      spec: 'https://site.example/private' },
    browsingContext: { originAttributes: { userContextId: 7, privateBrowsingId: 0 },
      currentWindowGlobal: { innerWindowId: 12 } } };
}
const gBrowser = { selectedBrowser: makeBrowser() };
const opened = [], hidden = [];
const context = { Ci, document, gBrowser, Object, encodeURIComponent,
  PanelMultiView: { hidePopup(popup) { hidden.push(popup); } },
  openTrustedLinkIn(...args) { opened.push(args); },
};
vm.createContext(context);
vm.runInContext('this.handler = ({' + input.methods + '});', context);
const handler = context.handler;
(async () => { BODY })().catch(error => { console.error(error); process.exitCode = 1; });
"""


class SecurityUITest(unittest.TestCase):
    def run_methods(self, body: str) -> None:
        source = (SOURCE / "browser/base/content/browser-siteIdentity.js").read_text()
        methods = source.split("  _getGoodBearRussianPKIDetails(", 1)[1].split(
            "\n  refreshIdentityPopup()", 1)[0]
        result = subprocess.run(
            [str(NODE), "-e", HARNESS.replace("BODY", body)],
            input=json.dumps({"methods": "_getGoodBearRussianPKIDetails(" + methods}),
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_domain_and_verified_chain_supply_text_only_details(self) -> None:
        self.run_methods("""
          const details = handler._getGoodBearRussianPKIDetails();
          assert.ok(Object.isFrozen(details));
          assert.equal(details.hostname, 'site.example');
          assert.equal(details.root, 'Actual root');
          handler._updateGoodBearRussianPKIDetails();
          assert.equal(fields.get('goodbear-russian-pki-leaf').textContent,
            '<script>untrusted subject</script>');
          assert.equal(fields.get('goodbear-russian-pki-details').hidden, false);
          assert.equal(fields.get('goodbear-russian-pki-view-certificate').disabled, false);
          assert.equal(handler._showGoodBearRussianPKICertificate(), true);
          assert.equal(opened.length, 1);
          assert.equal(opened[0][0], 'about:certificate?cert=YWJj%2B%2F%3D&cert=cm9vdA%3D%3D');
          assert.equal(opened[0][2].userContextId, 7);
        """)

    def test_standard_invalid_private_overridden_and_missing_chain_fail_closed(self) -> None:
        self.run_methods("""
          for (const change of [
            b => b.securityUI.secInfo.goodBearTrustDomain = 1,
            b => b.securityUI.secInfo.goodBearTrustDomain = 0,
            b => b.securityUI.secInfo.goodBearTrustDomain = 99,
            b => delete b.securityUI.secInfo.goodBearTrustDomain,
            b => b.securityUI.state = 0,
            b => b.securityUI.state = 3,
            b => b.securityUI.secInfo.errorCode = -1,
            b => b.browsingContext.originAttributes.userContextId = 0,
            b => b.browsingContext.originAttributes.userContextId = '7',
            b => b.browsingContext.originAttributes.privateBrowsingId = 1,
            b => delete b.browsingContext.currentWindowGlobal.innerWindowId,
            b => b.securityUI.secInfo.succeededCertChain = [],
            b => delete b.securityUI.secInfo.succeededCertChain,
            b => b.securityUI.secInfo.serverCert = {},
            b => b.securityUI.secInfo.succeededCertChain[1].sha256Fingerprint = 'not a fingerprint',
            b => b.securityUI.secInfo.succeededCertChain[1].getBase64DERString = () => '',
          ]) {
            const browser = makeBrowser(); change(browser);
            assert.equal(handler._getGoodBearRussianPKIDetails(browser), null);
          }
          assert.equal(opened.length, 0);
        """)

    def test_tab_document_or_security_snapshot_change_refuses_viewer(self) -> None:
        self.run_methods("""
          for (const change of [
            () => gBrowser.selectedBrowser = makeBrowser(),
            () => gBrowser.selectedBrowser.browsingContext.currentWindowGlobal.innerWindowId++,
            () => gBrowser.selectedBrowser.securityUI.secInfo = makeBrowser().securityUI.secInfo,
            () => gBrowser.selectedBrowser.currentURI.spec = 'https://site.example/changed',
          ]) {
            gBrowser.selectedBrowser = makeBrowser();
            handler._updateGoodBearRussianPKIDetails();
            change();
            assert.equal(handler._showGoodBearRussianPKICertificate(), false);
          }
          assert.equal(opened.length, 0);
        """)

    def test_missing_subject_localizes_and_failed_state_clears_old_fields(self) -> None:
        self.run_methods("""
          gBrowser.selectedBrowser.securityUI.secInfo.serverCert.subjectName = '';
          handler._updateGoodBearRussianPKIDetails();
          assert.equal(fields.get('goodbear-russian-pki-leaf').attrs['data-l10n-id'],
            'identity-goodbear-russian-pki-empty-name');
          gBrowser.selectedBrowser.securityUI.secInfo.goodBearTrustDomain = 1;
          handler._updateGoodBearRussianPKIDetails();
          for (const name of ['hostname','leaf','issuer','root','fingerprint']) {
            const field = fields.get('goodbear-russian-pki-' + name);
            assert.equal(field.textContent, '');
            assert.equal(field.attrs['data-l10n-id'], undefined);
          }
          assert.equal(fields.get('goodbear-russian-pki-details').hidden, true);
          assert.equal(handler._showGoodBearRussianPKICertificate(), false);
        """)

    def test_container_marker_is_independent_and_clears_on_ordinary_switch(self) -> None:
        source = (SOURCE / "browser/components/tabbrowser/Tabbrowser.sys.mjs").read_text()
        method = source.split("  #updateUserContextUIIndicator() {", 1)[1].split(
            "\n  // Begin forwarded browser properties", 1)[0]
        program = r"""
          const assert = require('node:assert/strict');
          const method = JSON.parse(require('node:fs').readFileSync(0,'utf8'));
          function element() { const values = new Set(); values.remove = values.delete;
            values.contains = values.has;
            return { attrs: {}, classList: values, hidden: false, textContent: '',
              removeAttribute(key) { delete this.attrs[key]; },
              setAttribute(key,value) { this.attrs[key]=value; } }; }
          const elements = new Map(['userContext-icons','userContext-label','userContext-indicator']
            .map(id => [id,element()]));
          const document = { getElementById(id) { return elements.get(id); },
            l10n: { setAttributes(el,id) { el.attrs['data-l10n-id']=id; } } };
          let selected = 7;
          const managed = { managedPurpose:'goodbear-russian-pki',color:'gray',icon:'fence' };
          const ordinary = { name:'ordinary',color:'blue',icon:'cart' };
          const lazy = { ContextualIdentityService: {
            getPublicIdentityFromId(id) { return id===7 ? managed : ordinary; },
            getUserContextLabel() { return 'ordinary'; } } };
          const tabbrowser = eval('({_update() {'+method+'})');
          tabbrowser.document=document;
          tabbrowser.selectedBrowser={getAttribute() { return selected; }};
          tabbrowser._update();
          assert.equal(elements.get('userContext-label').attrs['data-l10n-id'],
            'urlbar-goodbear-russian-pki-container-label');
          const box=elements.get('userContext-icons');
          assert.equal(box.hidden,false);
          assert.equal(box.attrs['data-l10n-id'],'urlbar-goodbear-russian-pki-container-marker');
          box.attrs['aria-label']='managed';
          selected=2; tabbrowser._update();
          assert.equal(box.attrs['data-l10n-id'],undefined);
          assert.equal(box.attrs['aria-label'],undefined);
          assert.equal(box.attrs.tooltiptext,'ordinary');
          assert.equal(elements.get('userContext-label').textContent,'ordinary');
          selected=0; tabbrowser._update(); assert.equal(box.hidden,true);
          assert.equal(box.attrs.tooltiptext,undefined);
        """
        result = subprocess.run([str(NODE), "-e", program], input=json.dumps(method),
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_container_translation_revokes_scope_before_failing(self) -> None:
        source = (SOURCE / "browser/components/GoodBearRussianPKIContainer.sys.mjs").read_text()
        methods = source.split("  ensureContainer() {", 1)[1].split("\n  _isEnabled()", 1)[0]
        identity_guard = source.split("function isUsableManagedIdentity(identity) {", 1)[1].split(
            "\nfunction canonicalizeAssignmentOrigin", 1)[0]
        program = r"""
          const assert = require('node:assert/strict');
          const input=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
          const GOOD_BEAR_RUSSIAN_PKI_CONTAINER_PURPOSE='goodbear-russian-pki';
          const CONTAINER_ICON='fence', CONTAINER_COLOR='gray';
          const isUsableManagedIdentity=eval('(function(identity){'+input.guard+')');
          let mode='valid', cleared=0, created=0, identity=null;
          class Localization {
            constructor(resources,sync) {
              assert.deepEqual(resources,['browser/browser.ftl']); assert.equal(sync,true);
            }
            formatValueSync(id) {
              assert.equal(id,'urlbar-goodbear-russian-pki-container-label');
              if(mode==='throws') throw Error('Unavailable bundle');
              return mode==='missing' ? null : mode==='empty' ? ' ' : 'Localized container';
            }
          }
          const manager=new (eval('(class {ensureContainer(){'+input.methods+'})'))();
          manager._dedicatedUserContextId=77;
          manager._clearPublishedContainer=()=>cleared++;
          manager._isEnabled=()=>true;
          manager._publishValidatedContainer=value=>value;
          manager._identityService={
            getPublicIdentities() { return identity ? [identity] : []; },
            getPublicIdentityFromId() { return identity; },
            createManagedIdentity(name,icon,color,managedPurpose) {
              created++; return identity={name,icon,color,managedPurpose,public:true,userContextId:7};
            },
            update(id,name,icon,color) { Object.assign(identity,{name,icon,color}); },
          };
          for(mode of ['throws','missing','empty']) {
            assert.equal(manager.ensureContainer(),null);
            assert.equal(manager._dedicatedUserContextId,null);
            assert.equal(created,0);
          }
          assert.equal(cleared,3);
          mode='valid';
          assert.equal(manager.ensureContainer().name,'Localized container');
          identity.name='user supplied name';
          assert.equal(manager.ensureContainer().name,'Localized container');
          assert.equal(created,1);
        """
        result = subprocess.run([str(NODE), "-e", program],
                                input=json.dumps({"methods": methods, "guard": identity_guard}),
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
