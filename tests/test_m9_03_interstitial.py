"""Run actual chrome controller methods in Node; not native browser evidence."""

import os
import json
import re
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from host_build_context import SOURCE, TOOLCHAIN

OWNER_ROOT = Path(os.environ.get("GOODBEAR_INTERSTITIAL_SOURCE", SOURCE))
MODULE = OWNER_ROOT / "browser/components/GoodBearRussianPKIInterstitial.sys.mjs"
GLUE = OWNER_ROOT / "browser/components/BrowserGlue.sys.mjs"

BOOTSTRAP = r'''
const assert = require("node:assert/strict");
let model, closeDialog, openCalls = [], backCalls = 0, blankCalls = 0;
let enabled = true, malformed = undefined, promptCalls = 0;
let viewer = null, identity = { userContextId:17, managedPurpose:"goodbear-russian-pki" };
const prefObservers = new Set(), observers = new Map(), events = new Map();
const manager = { dedicatedUserContextId:17 };
const Services = {
  prefs: { getBoolPref:()=>enabled, addObserver:(_,o)=>prefObservers.add(o),
           removeObserver:(_,o)=>prefObservers.delete(o) },
  obs: { addObserver(o,t) { if (!observers.has(t)) observers.set(t,new Set()); observers.get(t).add(o); },
         removeObserver(o,t) { observers.get(t).delete(o); } },
  scriptSecurityManager: { getSystemPrincipal:()=>"SYSTEM" },
  io: { newURI:url=>({scheme:"https",asciiHost:new URL(url).hostname,port:-1}) },
};
const ChromeUtils = {
  defineESModuleGetters(target) { Object.assign(target, {
    GoodBearRussianPKIContainer:manager,
    ContextualIdentityService:{getPublicIdentityFromId:()=>identity},
  }); },
  generateQI:()=>()=>{},
};
const Ci = { nsIWebProgress:{NOTIFY_LOCATION:1} };
const Controller = Function("ChromeUtils","Services","Ci",process.argv[1].replace("export const ","const ")+
  "; return GoodBearRussianPKIInterstitial;")(ChromeUtils,Services,Ci);
const target = { addEventListener:(n,f)=>events.set(n,f), removeEventListener:n=>events.delete(n) };
const windowGlobal = { innerWindowId:77, getActor:()=>({getCertificateViewer:()=>viewer}) };
const context = { currentWindowGlobal:windowGlobal, originAttributes:{userContextId:0,privateBrowsingId:0} };
context.top = context;
const browser = {
  isConnected:true, browsingContext:context, currentURI:{spec:"https://stopped.example.test/"}, canGoBack:true,
  goBack() { backCalls++; },
  fixupAndLoadURIString(url, options) { assert.equal(url,"about:blank"); assert.deepEqual(Object.keys(options),["triggeringPrincipal"]); blankCalls++; },
  webProgress:{addProgressListener:o=>events.set("location",o),removeProgressListener:()=>events.delete("location")},
};
const window = {
  closed:false,
  Localization:class {
    constructor(resources,sync) { assert.deepEqual(resources,["browser/browser.ftl"]); assert.equal(sync,true); }
    formatValuesSync(ids) {
      if (malformed === "throw") throw Error("localized fixture failure");
      return malformed === undefined ? ids.map(id=>"localized:"+id) : malformed;
    }
  },
  gBrowser: { selectedBrowser:browser, tabContainer:target, getTabForBrowser:()=>target,
    removeTab:()=>{},
    getTabDialogBox(b) { assert.equal(b,browser); return {
      open(url,options,data) {
        promptCalls++; model=data;
        assert.equal(url,"chrome://browser/content/goodbearRussianPKIInterstitial.xhtml");
        assert.equal(options.keepOpenSameOriginNav,false); assert.equal(options.hideContent,true);
        assert.equal(options.allowDuplicateDialogs,false);
        const closedPromise = new Promise(resolve=>closeDialog=resolve);
        return {closedPromise,dialog:{abort() { closeDialog(); }}};
      },
    }; },
  },
};
browser.documentGlobal=window;
const lazy = { GoodBearRussianPKIContainer:manager, GoodBearRussianPKIInterstitial:Controller };
const exactHTTPSOriginKey = uri=>"https\0"+uri.asciiHost+"\0"+"443";
const policy = eval("({"+process.argv[2]+"})");
policy._pendingTrustChangeNavigations = new Map();
policy._openLinkIn = (win,url,options)=>{
  assert.equal(win,window);
  assert.equal(options.userContextId,17);
  assert.equal(options.triggeringPrincipal,"SYSTEM");
  assert.deepEqual(Object.keys(options).sort(),["forceForeground","resolveOnNewTabCreated","triggeringPrincipal","userContextId"].sort());
  openCalls.push({url,options});
  options.resolveOnNewTabCreated({browsingContext:{id:99}});
};
const request = (body=false,changed=false)=>policy._handleAddressOnlyChoice(window,browser,
  "https://stopped.example.test/private?address-only",17,false,body,false,changed);
const reset = ()=>{model=null;openCalls=[];backCalls=0;blankCalls=0;promptCalls=0;};
const toggle = value=>{enabled=value;for(const observer of [...prefObservers]) observer.observe(null,"nsPref:changed","security.goodbear.russian_pki.enabled");};
const notifyIdentity = ()=>{for(const observer of [...(observers.get("contextual-identity-deleted")??[])]) observer.observe({wrappedJSObject:{userContextId:17}});};
const clean = ()=>{assert.equal(prefObservers.size,0);assert.ok([...observers.values()].every(set=>!set.size));assert.equal(events.size,0);};
'''


def run_controller(script):
    glue = GLUE.read_text()
    start = glue.index("\n  async _handleAddressOnlyChoice(")
    end = glue.index("\n  _openLinkIn(", start)
    result = subprocess.run([str(TOOLCHAIN / "node/bin/node"), "-e",
                             BOOTSTRAP + "\n(async()=>{\n" + script + "\n})().catch(error=>{console.error(error);process.exitCode=1;});",
                             MODULE.read_text(), glue[start:end]], text=True, capture_output=True, check=False)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)


CHOICES = r'''
for (const body of [false,true]) for (const changed of [false,true]) for(const choice of ["open","back","cancel"]) {
  reset(); const pending=request(body,changed);
  assert.equal(promptCalls,1); assert.ok(model);
  assert.equal(model.title,"localized:goodbear-russian-pki-interstitial-"+(changed?"trust-changed-title":body?"body-title":"title"));
  assert.equal(model.description,"localized:goodbear-russian-pki-interstitial-"+(changed?"trust-changed-description":body?"body-description":"description"));
  assert.equal(Boolean(model.bodyDescription),body&&changed);
  assert.equal(model.canViewCertificate,false);
  if(choice!=="cancel") assert.equal(await model.choose(choice),true);
  closeDialog(); await pending;
  assert.equal(openCalls.length,choice==="open"?1:0);
  assert.equal(backCalls,choice==="back"?1:0);
  assert.equal(blankCalls,0); clean();
}
'''

LOCALIZATION_FAILURES = r'''
for (const failure of ["throw",null,[],["title"],Array(9).fill(null),Array(9).fill(" "),Array(9).fill(1)]) {
  malformed=failure;
  for(const body of [false,true]) for(const changed of [false,true]) {
    reset(); await request(body,changed);
    assert.equal(promptCalls,0); assert.equal(openCalls.length,0); assert.equal(backCalls,0); assert.equal(blankCalls,0); clean();
  }
}
'''


class InterstitialControllerTest(unittest.TestCase):
    def test_all_body_trust_choices_keep_actual_address_only_boundary(self):
        run_controller(CHOICES)

    def test_missing_throwing_malformed_fluent_never_authorizes(self):
        run_controller(LOCALIZATION_FAILURES)

    def test_no_history_back_is_only_safe_blank_navigation(self):
        run_controller('browser.canGoBack=false; const pending=request(true,true); await model.choose("back"); closeDialog(); await pending; assert.equal(blankCalls,1); assert.equal(backCalls,0); assert.equal(openCalls.length,0); clean();')

    def test_dismissal_after_open_choice_before_close_completion_cannot_authorize(self):
        run_controller('const pending=request(true,true); await model.choose("open"); toggle(false); toggle(true); closeDialog(); await pending; assert.equal(openCalls.length,0); clean();')

    def test_tab_change_is_permanent_even_when_user_returns(self):
        run_controller('const pending=request(true,true); const stale=model; window.gBrowser.selectedBrowser={}; events.get("TabSelect")(); window.gBrowser.selectedBrowser=browser; await stale.choose("open"); await pending; assert.equal(openCalls.length,0); clean();')

    def test_identity_deletion_recreation_with_same_id_does_not_revive(self):
        run_controller('const pending=request(true,true); const stale=model; notifyIdentity(); identity={userContextId:17,managedPurpose:"goodbear-russian-pki"}; await stale.choose("open"); await pending; assert.equal(openCalls.length,0); clean();')

    def test_any_top_level_location_event_including_same_document_revokes(self):
        run_controller('const pending=request(true,true); const stale=model; events.get("location").onLocationChange({isTopLevel:true},null,null,1); await stale.choose("open"); await pending; assert.equal(openCalls.length,0); clean();')

    def test_replaced_inner_window_and_tab_close_reject_late_choice(self):
        run_controller('const pending=request(true,true); context.currentWindowGlobal={innerWindowId:78}; await model.choose("open"); await pending; assert.equal(openCalls.length,0); clean();')
        run_controller('const pending=request(true,true); const stale=model; events.get("TabClose")(); await stale.choose("open"); await pending; assert.equal(openCalls.length,0); clean();')

    def test_repeated_button_cannot_commit_twice(self):
        run_controller('const pending=request(true,true); await model.choose("open"); await model.choose("open"); closeDialog(); await pending; assert.equal(openCalls.length,0); clean();')

    def test_certificate_view_revokes_on_native_viewer_tab_select_without_routing(self):
        run_controller('let viewed=0; viewer=async current=>{assert.equal(current(),true);viewed++;window.gBrowser.selectedBrowser={};events.get("TabSelect")();}; const pending=request(true,true); assert.equal(model.canViewCertificate,true); await model.choose("certificate"); await pending; assert.equal(viewed,1); assert.equal(openCalls.length,0); assert.equal(backCalls,0); clean();')

    def test_native_upload_presence_is_never_read_or_treated_as_safe_get(self):
        child = (OWNER_ROOT / "browser/actors/GoodBearRussianPKICertificateErrorChild.sys.mjs").read_text()
        child = re.sub(r"export \{[^}]+\};", "", child.replace("export class ", "class "))
        script = "const actorSource=" + json.dumps(child) + r''';
const candidate = Function("Ci","JSWindowActorChild",actorSource+";return getRussianPKIRoutingCandidate;")(
  {nsIHttpChannel:"http",nsIUploadChannel:"upload"},class {});
const stream = new Proxy({}, {get(){throw Error("upload bytes must never be read");}});
for(const [method,upload,fail,expected] of [["GET",null,false,false],["HEAD",null,false,false],
  ["GET",stream,false,true],["HEAD",stream,false,true],["POST",null,false,true],
  ["GET",undefined,false,true],["GET",null,true,true]]) {
  const channel={securityInfo:{goodBearRussianPKIRequired:true},requestMethod:method,
    URI:{scheme:"https",asciiHost:"fixture.test",spec:"https://fixture.test/"},uploadStream:upload,
    QueryInterface(iid) {if(iid==="upload"&&fail)throw Error("QI unavailable");return this;}};
  const result=candidate({failedChannel:channel});
  assert.equal(result.hasRequestBody,expected);
  assert.deepEqual(Object.keys(result).sort(),["hasRequestBody","method","url"]);
}
'''
        run_controller(script)

    def test_loading_store_retry_stays_bound_to_original_window_global(self):
        glue = GLUE.read_text()
        start = glue.index("\n  openAddressOnlyAfterRussianPKICertificateError(")
        end = glue.index("\n};", start)
        script = "const routingSource=" + json.dumps(glue[start:end]) + r''';
const getBrowserWindow=()=>window;
Object.assign(manager,{routingStateLoaded:false,assignmentStore:{isAssigned:()=>false},trustHistoryStore:{get:()=>null}});
let finishLoad, scheduled=0;
manager.initialize=()=>new Promise(resolve=>finishLoad=resolve);
const routing=eval("({"+routingSource+"})");
routing._scheduleAddressOnlyOpen=()=>scheduled++;
assert.equal(routing.openAddressOnlyAfterRussianPKICertificateError(browser,"https://fixture.test/","GET",false),true);
context.currentWindowGlobal={innerWindowId:78}; manager.routingStateLoaded=true; finishLoad();
await Promise.resolve(); await Promise.resolve();
assert.equal(scheduled,0,"an old native candidate cannot attach to the new page after store loading");
'''
        run_controller(script)

    def test_malformed_body_marker_blocks_auto_route_even_for_get_head(self):
        glue = GLUE.read_text()
        start = glue.index("\n  openAddressOnlyAfterRussianPKICertificateError(")
        end = glue.index("\n};", start)
        script = "const routingSource=" + json.dumps(glue[start:end]) + r''';
const getBrowserWindow=()=>window;
Object.assign(manager,{routingStateLoaded:true,assignmentStore:{isAssigned:()=>false},trustHistoryStore:{get:()=>null}});
const routing=eval("({"+routingSource+"})");
let options; routing._scheduleAddressOnlyOpen=(...args)=>options=args[3];
for(const method of ["GET","HEAD","POST"]) for(const flag of [false,true,undefined,null,"false",0,{}]) {
  assert.equal(routing.openAddressOnlyAfterRussianPKICertificateError(browser,"https://fixture.test/",method,flag),true);
  assert.equal(options.autoOpen,flag===false&&method!=="POST");
  assert.equal(options.hasRequestBody,flag!==false||method==="POST");
}
'''
        run_controller(script)

    def test_assigned_error_requires_native_policy_status_and_ordinary_document(self):
        child = (OWNER_ROOT / "browser/actors/GoodBearRussianPKICertificateErrorChild.sys.mjs").read_text()
        child = re.sub(r"export \{[^}]+\};", "", child.replace("export class ", "class "))
        script = "const actorSource=" + json.dumps(child) + r''';
const candidate = Function("Ci","Cr","JSWindowActorChild",actorSource+";return getAssignedPolicyRoutingCandidate;")(
  {nsIHttpChannel:"http",nsIUploadChannel:"upload",nsIContentPolicy:{TYPE_DOCUMENT:1}},
  {NS_ERROR_BLOCKED_BY_POLICY:99},class {});
const fixture = ()=>({status:99,requestMethod:"GET",uploadStream:{},
  URI:{scheme:"https",asciiHost:"fixture.test",spec:"https://fixture.test/"},
  loadInfo:{externalContentPolicyType:1,originAttributes:{userContextId:0,privateBrowsingId:0}},
  QueryInterface(){return this;}});
let channel=fixture();
assert.deepEqual(candidate({failedChannel:channel}),{url:"https://fixture.test/",method:"GET",hasRequestBody:true});
channel.uploadStream=null;assert.equal(candidate({failedChannel:channel}).hasRequestBody,false);
for(const mutate of [c=>c.status=100,c=>c.status="99",c=>c.loadInfo.externalContentPolicyType=2,
  c=>c.loadInfo.originAttributes.userContextId=6,c=>c.loadInfo.originAttributes.privateBrowsingId=1,
  c=>c.loadInfo.originAttributes=null,c=>c.URI.scheme="http"]) {
  channel=fixture();mutate(channel);assert.equal(candidate({failedChannel:channel}),null);
}
'''
        run_controller(script)

    def test_assigned_error_rechecks_exact_assignment_and_old_window_after_loading(self):
        glue = GLUE.read_text()
        start = glue.index("\n  openAddressOnlyAfterAssignedPolicyError(")
        end = glue.index("\n  // Called only by the certificate-error actor", start)
        script = "const routingSource=" + json.dumps(glue[start:end]) + r''';
const getBrowserWindow=()=>window;
let assigned=true, decisionId=17;
Object.assign(manager,{routingStateLoaded:true,assignmentStore:{isAssigned:()=>assigned},
  getLoadDecision:(_uri,_context,options)=>({type:enabled?(options.hasRequestBody?"body-blocked":"isolated"):"ordinary",userContextId:decisionId})});
const routing=eval("({"+routingSource+"})");
let scheduled=[];routing._scheduleAddressOnlyOpen=(...args)=>scheduled.push(args);
const invoke=(flag,expected=windowGlobal)=>routing.openAddressOnlyAfterAssignedPolicyError(
  browser,"https://fixture.test/","GET",flag,expected,77);
assert.equal(invoke(true),true);assert.equal(scheduled.pop()[3].autoOpen,false);
assert.equal(invoke(false),true);assert.equal(scheduled.pop()[3].autoOpen,true);
assigned=false;assert.equal(invoke(true),false);assigned=true;
enabled=false;assert.equal(invoke(true),false);enabled=true;
decisionId=18;assert.equal(invoke(true),false);decisionId=17;
assert.equal(invoke(true,{innerWindowId:77}),false);
manager.routingStateLoaded=false;let finishLoad;
manager.initialize=()=>new Promise(resolve=>finishLoad=resolve);
assert.equal(invoke(true),true);context.currentWindowGlobal={innerWindowId:78};
manager.routingStateLoaded=true;finishLoad();await Promise.resolve();await Promise.resolve();
assert.equal(scheduled.length,0);
'''
        run_controller(script)


if __name__ == "__main__":
    unittest.main()
