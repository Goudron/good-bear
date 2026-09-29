#!/usr/bin/env python3
"""Offline Fluent AST and consumer audit; never a localized runtime acceptance."""

from __future__ import annotations

import hashlib
from functools import lru_cache
import json
from pathlib import Path
import re
import sys

from host_build_context import L10N_BASE, SOURCE


class FluentAuditError(RuntimeError):
    pass


CUSTOM_PREFIXES = ("goodbear-", "identity-goodbear-", "urlbar-goodbear-")
PLURAL_KEYS = {"zero", "one", "two", "few", "many", "other"}
RESOURCES = {
    "browser/browser.ftl": (
        "browser/locales/en-US/browser/browser.ftl", "ru/browser/browser/browser.ftl"),
    "browser/aboutDialog.ftl": (
        "browser/locales/en-US/browser/aboutDialog.ftl", "ru/browser/browser/aboutDialog.ftl"),
    "browser/protectionsPanel.ftl": (
        "browser/locales/en-US/browser/protectionsPanel.ftl", "ru/browser/browser/protectionsPanel.ftl"),
    "branding/brand.ftl": (
        "browser/branding/goodbear/locales/en-US/brand.ftl", None),
    "browser/preferences/goodBearRussianPKI.ftl": (
        "browser/locales/en-US/browser/preferences/goodBearRussianPKI.ftl",
        "ru/browser/browser/preferences/goodBearRussianPKI.ftl"),
}
OWNERS = {
    "browser/base/content/navigator-toolbox.inc.xhtml": "browser",
    "browser/base/content/browser-siteIdentity.js": "browser",
    "browser/base/content/browser-trustPanel.js": "browser",
    "browser/components/controlcenter/content/identityPanel.inc.xhtml": "browser",
    "browser/components/controlcenter/content/trustPanel.inc.xhtml": "browser",
    "browser/components/controlcenter/content/securityInformation.inc.xhtml": "browser",
    "browser/components/tabbrowser/Tabbrowser.sys.mjs": "browser",
    "browser/components/GoodBearRussianPKIContainer.sys.mjs": "goodbear_container",
    "browser/base/content/aboutDialog.xhtml": "about",
    "browser/base/content/aboutDialog.js": "about",
    "browser/components/BrowserGlue.sys.mjs": "goodbear_prompt",
    "browser/components/GoodBearRussianPKIInterstitial.sys.mjs": "goodbear_interstitial",
    "browser/base/content/goodbearRussianPKIInterstitial.xhtml": "interstitial_document",
    "browser/base/content/goodbearRussianPKIInterstitial.js": "interstitial_document",
    "browser/components/preferences/goodBearRussianPKI.inc.xhtml": "preferences",
    "browser/components/preferences/goodBearRussianPKI.js": "preferences",
}
REGISTRATION_OWNERS = {
    "browser": "browser/base/content/browser.xhtml",
    "about": "browser/base/content/aboutDialog.xhtml",
    "preferences": "browser/components/preferences/preferences.xhtml",
    "interstitial_document": "browser/base/content/goodbearRussianPKIInterstitial.xhtml",
}


@lru_cache(maxsize=1)
def parser():
    # Reuse the official parser from the exact materialized Firefox source.
    # No pip/network bootstrap or regex approximation of Fluent syntax.
    vendor = SOURCE / "third_party/python/fluent.syntax"
    if not vendor.is_dir():
        raise FluentAuditError(f"pinned Fluent parser is unavailable: {vendor}")
    sys.path.insert(0, str(vendor))
    from fluent.syntax import FluentParser
    return FluentParser(with_spans=False)


def catalogue(text: str, owner: str) -> dict:
    entries = {}
    for entry in parser().parse(text).to_json()["body"]:
        kind = entry["type"]
        if kind == "Junk":
            raise FluentAuditError(f"{owner}: invalid Fluent syntax: {entry.get('annotations')}")
        if kind not in {"Message", "Term"}:
            continue
        identifier = ("-" if kind == "Term" else "") + entry["id"]["name"]
        if identifier in entries:
            raise FluentAuditError(f"{owner}: duplicate Fluent ID {identifier}")
        attributes = [attribute["id"]["name"] for attribute in entry["attributes"]]
        if len(attributes) != len(set(attributes)):
            raise FluentAuditError(f"{owner}: duplicate attribute in {identifier}")
        entries[identifier] = entry
    return entries


def walk(value):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)


def fields(entry: dict) -> dict:
    result = {attribute["id"]["name"]: attribute["value"] for attribute in entry["attributes"]}
    if entry["value"] is not None:
        result["value"] = entry["value"]
    return result


def literals(pattern: dict) -> str:
    return "".join(node["value"] for node in walk(pattern) if node.get("type") == "TextElement")


def references(pattern: dict) -> set[tuple[str, str, str]]:
    return {
        (node["type"], node["id"]["name"], (node.get("attribute") or {}).get("name", ""))
        for node in walk(pattern)
        if node.get("type") in {"VariableReference", "MessageReference", "TermReference", "FunctionReference"}
    }


def expression_identity(value):
    if isinstance(value, dict):
        return {key: expression_identity(item) for key, item in value.items() if key != "span"}
    if isinstance(value, list):
        return [expression_identity(item) for item in value]
    return value


def selector_shapes(pattern: dict) -> list[str]:
    shapes = []
    for node in walk(pattern):
        if node.get("type") != "SelectExpression":
            continue
        variants = node["variants"]
        keys = [(variant["key"]["type"], variant["key"].get("name", variant["key"].get("value")))
                for variant in variants]
        named = {key for kind, key in keys if kind == "Identifier"}
        # Russian legitimately uses one/few/many and may default to many.
        # Enum keys and explicit numeric branches must still match exactly.
        plural = bool(named) and named <= PLURAL_KEYS
        defaults = [keys[index] for index, variant in enumerate(variants) if variant["default"]]
        if plural:
            defaults = [("PluralCategory", "locale-default") if kind == "Identifier" else (kind, key)
                        for kind, key in defaults]
        normalized = [item for item in keys if not (plural and item[0] == "Identifier")]
        shapes.append(json.dumps({
            "selector": expression_identity(node["selector"]),
            "keys": sorted(normalized), "plural": plural, "defaults": defaults,
        }, sort_keys=True))
    return sorted(shapes)


def message_issues(original: dict, russian: dict) -> list[str]:
    source_fields, ru_fields = fields(original), fields(russian)
    problems = []
    if set(source_fields) != set(ru_fields):
        problems.append(f"value/attribute mismatch: expected {sorted(source_fields)}, found {sorted(ru_fields)}")
    for name in source_fields.keys() & ru_fields.keys():
        if references(source_fields[name]) != references(ru_fields[name]):
            problems.append(f"{name}: variable/message/term/function references changed")
        if selector_shapes(source_fields[name]) != selector_shapes(ru_fields[name]):
            problems.append(f"{name}: selector/default/explicit-branch contract changed")
        calls = lambda pattern: {
            json.dumps(expression_identity(node), sort_keys=True) for node in walk(pattern)
            if node.get("type") == "FunctionReference"
        }
        if calls(source_fields[name]) != calls(ru_fields[name]):
            problems.append(f"{name}: formatting function arguments changed")
        slots = lambda pattern: set(re.findall(r'data-l10n-name=["\']([^"\']+)', literals(pattern)))
        if slots(source_fields[name]) != slots(ru_fields[name]):
            problems.append(f"{name}: named markup slots changed")
    return problems


def accesskey_issues(entry: dict) -> list[str]:
    patterns = fields(entry)
    if "accesskey" not in patterns:
        return []
    key_pattern = patterns["accesskey"]
    choices = [node["value"] for node in walk(key_pattern) if node.get("type") == "Variant"]
    choices = choices or [key_pattern]
    if any(len(literals(choice).strip()) != 1 or references(choice) for choice in choices):
        return ["accesskey must resolve to one literal character per selector branch"]
    label = patterns.get("label", patterns.get("value"))
    if label and any(literals(choice).casefold() not in literals(label).casefold() for choice in choices):
        return ["accesskey character is absent from the translated label"]
    return []


def audit(source: Path = SOURCE, l10n: Path = L10N_BASE) -> dict:
    original, translated, ownership, hashes = {}, {}, {}, {}
    structural, fallback, bindings = [], [], []
    for resource, (source_owner, ru_owner) in RESOURCES.items():
        source_text = (source / source_owner).read_text(encoding="utf-8") if source_owner else None
        ru_text = (l10n / ru_owner).read_text(encoding="utf-8") if ru_owner else source_text
        # brand.ftl is intentionally Russian shared source under en-US; its
        # jar.mn packages it into @AB_CD@ rather than shipping an en-US locale.
        source_entries = catalogue(source_text, source_owner) if source_text is not None else {}
        ru_entries = catalogue(ru_text, ru_owner or source_owner)
        original.update(source_entries)
        translated.update(ru_entries)
        for identifier in source_entries.keys() | ru_entries.keys():
            ownership.setdefault(identifier, resource)
        for path, text in ((source_owner, source_text), (ru_owner, ru_text)):
            if path and text is not None:
                hashes[path] = hashlib.sha256(text.encode()).hexdigest()

    registrations = {}
    for bundle, owner in REGISTRATION_OWNERS.items():
        content = (source / owner).read_text(encoding="utf-8")
        registrations[bundle] = set(re.findall(r'<(?:html:)?link\s+rel="localization"\s+href="([^"]+)"', content))
        hashes[owner] = hashlib.sha256(content.encode()).hexdigest()
    prompt_owner = "browser/components/BrowserGlue.sys.mjs"
    prompt_source = (source / prompt_owner).read_text(encoding="utf-8")
    prompt = prompt_source.split("  _promptAddressOnlyOpen(", 1)[1].split("\n  _openAddressOnlyInContainer(", 1)[0]
    # BrowserGlue now delegates to the interstitial. Do not grant it an
    # implicit document bundle if a later edit reintroduces localized text.
    prompt_resources = re.findall(r'new\s+window\.Localization\(\s*\[([^\]]*)\]\s*,\s*true', prompt)
    registrations["goodbear_prompt"] = {
        resource for resources in prompt_resources
        for resource in re.findall(r'["\']([^"\']+\.ftl)["\']', resources)
    }
    interstitial_owner = "browser/components/GoodBearRussianPKIInterstitial.sys.mjs"
    interstitial_source = (source / interstitial_owner).read_text(encoding="utf-8")
    interstitial_resources = re.findall(
        r'new\s+window\.Localization\(\s*\[([^\]]*)\]\s*,\s*true', interstitial_source)
    # The model producer owns its bundle; the chrome document receives already
    # localized values and cannot supply resources to that independent API.
    registrations["goodbear_interstitial"] = {
        resource for resources in interstitial_resources
        for resource in re.findall(r'["\']([^"\']+\.ftl)["\']', resources)
    }
    container_owner = "browser/components/GoodBearRussianPKIContainer.sys.mjs"
    container_source = (source / container_owner).read_text(encoding="utf-8")
    container_resources = re.findall(
        r'new\s+Localization\(\s*\[([^\]]*)\]\s*,\s*true', container_source)
    registrations["goodbear_container"] = {
        resource for resources in container_resources
        for resource in re.findall(r'["\']([^"\']+\.ftl)["\']', resources)
    }
    brand_jar = (source / "browser/branding/goodbear/locales/jar.mn").read_text(encoding="utf-8")
    hashes["browser/branding/goodbear/locales/jar.mn"] = hashlib.sha256(brand_jar.encode()).hexdigest()
    if "[localization] @AB_CD@.jar:" not in brand_jar or "branding                                          (en-US/**/*.ftl)" not in brand_jar:
        bindings.append({"owner": "browser/branding/goodbear/locales/jar.mn", "issue": "shared Russian branding registration changed"})

    consumers = {}
    available = original.keys() | translated.keys()
    for owner, bundle in OWNERS.items():
        content = (source / owner).read_text(encoding="utf-8")
        hashes[owner] = hashlib.sha256(content.encode()).hexdigest()
        if owner.endswith("navigator-toolbox.inc.xhtml"):
            content = content.split('id="trust-icon-container"', 1)[1].split("</box>", 1)[0]
        elif owner == prompt_owner:
            content = prompt
        elif owner.endswith("Tabbrowser.sys.mjs"):
            content = content.split("  #updateUserContextUIIndicator() {", 1)[1].split(
                "\n  // Begin forwarded browser properties", 1)[0]
        elif owner == container_owner:
            content = content.split("  ensureContainer() {", 1)[1].split(
                "\n  _repairPresentation", 1)[0]
        direct = set(re.findall(r'data-l10n-id="([^"]+)"', content))
        direct.update(re.findall(r'(?:setAttributes\([^,]+,|formatValue\()\s*["\']([a-zA-Z][\w-]+)["\']', content))
        # Include constant and computed-family IDs present in these controllers.
        quoted = set(re.findall(r'["\']([a-zA-Z][\w-]+)["\']', content))
        direct.update(quoted & available)
        # Resolve literal ID arrays actually passed to the synchronous API.
        # Intersecting only with catalogues would miss a consumed ID deleted
        # from both source and Russian resources at once.
        for variable in re.findall(r'\.formatValuesSync\(\s*([A-Za-z_$][\w$]*)\s*\)', content):
            declared = re.search(r'\bconst\s+' + re.escape(variable) + r'\s*=\s*\[([^\]]*)\]', content)
            if declared:
                direct.update(re.findall(r'["\']([a-zA-Z][\w-]+)["\']', declared[1]))
        for identifier in direct:
            consumers.setdefault(identifier, []).append(owner)
            resource = ownership.get(identifier)
            if resource not in registrations[bundle]:
                bindings.append({"owner": owner, "id": identifier, "resource": resource,
                                 "issue": "message resource absent from registered bundle"})
            pending, visited = [identifier], set()
            while pending:
                referenced = pending.pop()
                if referenced in visited or referenced not in translated:
                    continue
                visited.add(referenced)
                if ownership[referenced] not in registrations[bundle]:
                    bindings.append({"owner": owner, "id": identifier, "reference": referenced,
                                     "issue": "referenced Russian resource is not registered in this bundle"})
                for pattern in fields(translated[referenced]).values():
                    pending.extend(("-" if kind == "TermReference" else "") + name
                                   for kind, name, _ in references(pattern)
                                   if kind in {"MessageReference", "TermReference"})

    custom = {identifier for identifier in translated if identifier.startswith(CUSTOM_PREFIXES)}
    selected = set(consumers) | custom
    # TrustPanel also forms IDs from blocker kind; cover that bounded family.
    selected.update(identifier for identifier in original if identifier.startswith("trustpanel-"))
    for identifier in sorted(selected):
        if identifier not in translated:
            fallback.append({"id": identifier, "issue": "missing Russian message; fallback/unresolved-ID risk"})
            continue
        entry = translated[identifier]
        if identifier in original:
            structural.extend({"id": identifier, "issue": issue}
                              for issue in message_issues(original[identifier], entry))
            for missing in fields(original[identifier]).keys() - fields(entry).keys():
                fallback.append({"id": identifier, "field": missing,
                                 "issue": "missing Russian value/attribute; fallback/unresolved-attribute risk"})
        structural.extend({"id": identifier, "issue": issue} for issue in accesskey_issues(entry))
        for field, pattern in fields(entry).items():
            for kind, name, attribute in references(pattern):
                if kind not in {"MessageReference", "TermReference"}:
                    continue
                reference = ("-" if kind == "TermReference" else "") + name
                target = translated.get(reference)
                if target is None or (attribute and attribute not in fields(target)):
                    fallback.append({"id": identifier, "field": field,
                                     "issue": f"unresolved Russian reference {reference}.{attribute}"})
        if identifier in custom and identifier not in consumers:
            bindings.append({"id": identifier, "resource": ownership[identifier],
                             "issue": "Russian string has no binding in the audited UI owners"})

    hardcoded = re.findall(r'"([^"\n]*[А-Яа-яЁё][^"\n]*)"', prompt)
    if hardcoded:
        bindings.append({"owner": prompt_owner, "issue": "Russian prompt literals bypass existing Fluent IDs",
                         "literal_count": len(hardcoded)})
    for owner in (interstitial_owner, "browser/base/content/goodbearRussianPKIInterstitial.js"):
        content = (source / owner).read_text(encoding="utf-8")
        if re.search(r'''(["'])([^"'\n]*[А-Яа-яЁё][^"'\n]*)\1''', content):
            bindings.append({"owner": owner, "issue": "Russian interstitial literals bypass Fluent"})
    if "browser/browser.ftl" not in registrations["interstitial_document"]:
        bindings.append({"owner": REGISTRATION_OWNERS["interstitial_document"],
                         "issue": "Russian interstitial document resource is not registered"})
    container_literals = re.findall(r'"([^"\n]*[А-Яа-яЁё][^"\n]*)"', container_source)
    if container_literals:
        bindings.append({"owner": container_owner, "issue": "Russian container literals bypass Fluent",
                         "literal_count": len(container_literals)})
    preferences_resource = "browser/preferences/goodBearRussianPKI.ftl"
    if preferences_resource not in registrations["preferences"]:
        bindings.append({"owner": REGISTRATION_OWNERS["preferences"], "resource": preferences_resource,
                         "issue": "Russian PKI settings resource is not registered"})
    return {
        "status": "blocked" if structural or fallback or bindings else "passed",
        "method": "pinned_fluent_ast_and_registered_consumers",
        "checked_message_count": len(selected),
        "bound_message_count": len(consumers),
        "structural_findings": structural,
        "fallback_findings": fallback,
        "binding_findings": bindings,
        "owner_sha256": hashes,
        "source_manifest_sha256": hashlib.sha256(
            json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "runtime_verified": False,
        "visible_english_observed": None,
        "visual_parity_proven": False,
        "upstream_rebase_regression_proven": False,
        "excluded_surfaces": {"installer_and_launcher": "non-Fluent packaging owners require separate runtime review"},
    }


def main() -> int:
    try:
        report = audit()
    except (FluentAuditError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return int(report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
