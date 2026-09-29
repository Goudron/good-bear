# Good Bear — Brandbook 1.0

**Product name:** Good Bear  
**Copyright for original Good Bear brand materials:** © 2026 Valery Ledovskoy <valery@ledovskoy.com>  
**Status:** normative visual and naming specification  
**Scope:** desktop Good Bear based on Mozilla Firefox open-source code

---

## 1. Brand idea

Good Bear is an independent desktop browser whose identity should communicate:

- calmness rather than alarmism;
- technical transparency;
- explicit security boundaries;
- a friendly but serious user experience;
- independent origin rather than imitation of Firefox/Mozilla branding.

The central visual character is a **good bear**. The bear is the Good Bear brand character, not a security trust symbol.

---

## 2. Canonical name

Primary product name:

```text
Good Bear
```

Preferred generic description:

```text
Good Bear browser
```

For package/repository identifiers, prefer independent Good Bear identifiers such as:

```text
goodbear
goodbear-browser
```

Exact platform-specific bundle/application identifiers must be defined during packaging work and checked for collisions.

---

## 3. Upstream attribution

Good Bear must not visually present itself as an official Firefox edition.

A suitable descriptive attribution is:

```text
Good Bear is an independent browser based on Mozilla Firefox open-source code.
```

The attribution belongs in:

- README;
- About/Legal area;
- source/release documentation;
- website legal/credits area.

It should **not** be used as the main product name in the title bar, application icon label or installer branding.

---

## 4. Mozilla/Firefox visual separation

Public Good Bear builds must use an independent visual identity.

Do not use as Good Bear product identity:

- Firefox logo;
- Firefox application icon;
- Mozilla logo;
- official Firefox wordmark;
- modified/recolored Firefox logo;
- a bear inserted into the Firefox flame/orbit composition;
- a confusingly similar Firefox icon silhouette.

Neutral browser UI icons that are functional rather than Mozilla trademarks may remain if their license permits and they are not themselves part of Firefox's distinctive brand identity.

---

## 5. Good Bear logo

### 5.1. Concept

The primary logo should be an original, readily recognizable bear mark with a calm/friendly character.

Desired traits:

- simple silhouette at 16–32 px;
- recognizable in monochrome;
- works in light and dark themes;
- not childish to the point of undermining security UI;
- not aggressive/military;
- not visually derived from Firefox artwork;
- no government emblems or state symbols as part of the primary logo.

### 5.2. Production requirement

Final logo files must have documented authorship/rights and should include at least:

```text
SVG master
16×16
24×24
32×32
48×48
64×64
128×128
256×256
512×512
1024×1024 where required by platform tooling
```

Platform packaging may generate required raster/icon container formats from the approved master.

### 5.3. Temporary artwork

Codex must not invent a final Good Bear logo by modifying Mozilla artwork.

Until final original artwork is supplied, use clearly designated development placeholders that cannot be mistaken for final release branding.

---

## 6. Mascot system

The bear may appear as an original illustration in user-facing non-security-state contexts.

Recommended states:

```text
neutral / welcome
thinking / setup
concerned / generic error
success / completed action
devices / sync or migration
backup / restore
empty state
```

The mascot may make the product warmer, but it must not replace precise security language.

---

## 7. Replacement of Firefox-specific artwork

Before public Good Bear 1.0 release, perform a branding audit and replace all user-visible Mozilla/Firefox identity artwork that would make the modified browser appear to be an official Firefox build.

Audit at least:

- application icons;
- executable/package icons;
- Windows Start/taskbar assets;
- macOS Dock/application assets;
- Linux desktop icons;
- installer graphics;
- About dialog/branding;
- first-run/onboarding illustrations;
- default browser promotional art;
- backup/restore artwork;
- device/sync artwork containing Firefox-specific mascot/brand elements;
- certificate/security error illustrations containing Firefox-specific mascot/brand artwork;
- update/restart artwork if branded;
- internal pages with a prominent Firefox logo;
- shortcut and launcher assets.

Do not blindly replace every SVG in Firefox. Preserve neutral functional UI artwork unless there is a branding or licensing reason to change it.

---

## 8. Security UI is not mascot UI

This is a mandatory Good Bear design principle.

> **The bear identifies the product. Security badges identify security state.**

Never use a smiling/angry bear alone to communicate certificate validity or trust domain.

Never use a bear plus national flag as the only Russian PKI indicator.

Security state must remain readable without interpreting the mascot.

---

## 9. Russian PKI Container identity

The special container required by Good Bear 1.0 has a technical identity separate from the product brand.

Preferred visible name:

```text
Russian PKI
```

Russian localization:

```text
Российская PKI
```

Alternative localized wording may be evaluated, but it must remain technically precise and avoid implying government ownership of Good Bear.

### 9.1. Container marker

The tab/container marker should use:

- a neutral shield/container symbol;
- text or accessible label identifying `Russian PKI`;
- a visual treatment distinct from normal tabs.

The marker must remain visible even when the current site inside the container uses a STANDARD Mozilla trust chain, because it describes **container identity**, not certificate identity.

---

## 10. Russian PKI certificate indicator

When the current connection is actually validated through the Good Bear Russian PKI trust domain, show a separate certificate/security indicator.

Candidate compact label:

```text
RU PKI
```

or:

```text
RU CA
```

Final copy should be usability-tested before release.

### 10.1. Do not use color alone

The state must remain distinguishable through:

- icon shape;
- accessible name;
- tooltip/popup copy;
- text label where practical.

Color is supplemental only.

### 10.2. Do not use official government insignia

Do not use:

- coat of arms;
- Ministry logo;
- FSTEC logo;
- official seals;
- imagery that implies certification or endorsement.

unless a separate legal review establishes an explicit basis for that use.

---

## 11. Relationship between container and certificate indicator

The UI must support all relevant combinations:

### Normal tab + STANDARD chain

```text
Good Bear normal tab
certificate trust = STANDARD
Russian PKI marker = absent
```

### Russian PKI Container + RUSSIAN_PKI chain

```text
container = Russian PKI
certificate trust = RUSSIAN_PKI
show container marker + Russian PKI certificate indicator
```

### Russian PKI Container + STANDARD chain

```text
container = Russian PKI
certificate trust = STANDARD
show container marker
hide Russian PKI certificate indicator
```

This distinction is mandatory.

---

## 12. Security copy style

Good Bear security language should be calm, factual and explicit.

Preferred:

```text
Сертификат успешно проверяется через Russian PKI.
Эта инфраструктура доверия разрешена только в изолированном контейнере Good Bear.
```

Avoid:

```text
Этот сайт полностью безопасен.
Государственный сертификат гарантирует безопасность.
Good Bear защищает вас от слежки.
```

The browser should describe what it verified, not promise properties TLS/container isolation cannot guarantee.

---

## 13. Trust-domain change UI

For `STANDARD → RUSSIAN_PKI`, the interstitial is a security boundary, not a marketing surface.

Requirements:

- no mascot animation that distracts from the decision;
- clear statement that the trust source changed;
- explain that ordinary browsing state will not be transferred;
- primary action: `Открыть изолированно`;
- secondary action: `Назад`;
- certificate details available;
- no red/green binary semantics implying inherently malicious/safe CA ownership.

A small concerned-bear illustration may be present only as secondary decoration if it does not reduce clarity.

---

## 14. Error illustrations

Firefox-specific mascot/brand artwork on error pages should be replaced by original Good Bear artwork before public release.

Suggested bear states:

- generic network error → mildly confused bear;
- certificate error → attentive/concerned bear;
- offline → resting/waiting bear;
- successful recovery → calm positive bear.

Do not change the technical meaning or severity of the underlying error merely to fit the mascot tone.

---

## 15. Visual tone

Good Bear should feel:

- modern;
- restrained;
- warm;
- trustworthy without claiming authority;
- technically literate.

Avoid:

- military/tactical aesthetics;
- state/government visual language;
- excessive national symbolism;
- cartoon overload in security-critical screens;
- copies of Firefox gradients/compositions designed to look unofficially official.

---

## 16. Color system

Final brand colors are **not yet fixed** in this 1.0 brandbook baseline.

Until an approved palette exists:

- reuse neutral platform/Firefox UI semantic colors where they are not brand marks;
- keep Good Bear brand colors in separate design tokens;
- keep security-state colors in separate semantic tokens;
- do not encode `Russian PKI` merely as a brand color;
- ensure light/dark/high-contrast support.

Do not hard-code a final Good Bear palette without a separate design decision.

---

## 17. Typography

Good Bear should normally use the browser/platform UI typography already used by the upstream interface unless there is a strong accessibility or branding reason to change it.

Do not add a third-party brand font to Good Bear 1.0 without:

- license review;
- distribution rights;
- platform testing;
- fallback definition.

Typography is lower priority than maintaining upstream compatibility and accessibility.

---

## 18. Accessibility

All Good Bear branding and security UI must support:

- keyboard navigation;
- screen-reader accessible names;
- non-color-only state communication;
- browser zoom;
- high-contrast/forced-colors modes where supported;
- readable text contrast;
- light and dark appearance.

A mascot illustration is decorative unless it conveys information; decorative art must not be the only source of information.

---

## 19. Localization

Brand name:

```text
Good Bear
```

should not normally be translated.

Technical UI strings should be localizable through the normal Firefox Fluent localization system rather than hard-coded in JavaScript/C++.

At minimum prepare English and Russian strings for Good Bear-specific Russian PKI UI.

---

## 20. About / Credits

The Good Bear About/Credits surface should clearly separate project ownership from upstream provenance.

Recommended content structure:

```text
Good Bear
Copyright © 2026 Valery Ledovskoy
valery@ledovskoy.com

Independent browser based on Mozilla Firefox open-source code.
Not affiliated with or endorsed by Mozilla.

Russian PKI support is an independent Good Bear feature and does not imply
endorsement or certification by the Ministry of Digital Development, FSTEC,
or any other government body.

Open-source licenses and third-party notices: [Legal Notices]
```

Do not put the email into every ordinary browser screen; use it in About/Legal/Credits and source metadata where appropriate.

---

## 21. Package and executable naming

Public packaging must not present the modified browser as `Firefox`.

When technically safe and compatible with the build/update architecture, prefer Good Bear-specific names for:

- package names;
- application display name;
- installer title;
- desktop launcher name;
- shortcuts;
- update channel/service identifiers;
- crash/report product branding;
- application bundle display metadata.

Changing deep application IDs may affect compatibility and must be researched rather than performed blindly.

---

## 22. Repository naming

A Good Bear source repository may truthfully describe its upstream relationship.

Preferred repository naming:

```text
goodbear-browser
goodbear
```

A patch-only repository may use `firefox` descriptively if needed to explain compatibility, but the public product must remain Good Bear.

---

## 23. Copyright on brand assets

Original Good Bear brand assets should carry, in accompanying metadata or relevant directory notice:

```text
Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>
All rights reserved unless otherwise stated.
```

Do not remove author/license metadata from third-party assets.

---

## 24. Codex branding rules

Codex must:

1. preserve Mozilla/third-party legal notices;
2. remove/replace user-facing Mozilla/Firefox product branding where required for a public modified build;
3. never manufacture a Good Bear logo by editing the Firefox logo;
4. use only approved Good Bear final assets for release builds;
5. keep mascot art separate from security-state semantics;
6. keep `Russian PKI Container` state separate from `RUSSIAN_PKI` certificate state;
7. keep Good Bear-specific UI strings localizable;
8. produce a branding audit report listing remaining Mozilla/Firefox user-visible assets after each major upstream rebase;
9. fail the release-branding check if prohibited official product marks remain in product identity surfaces;
10. never delete source/license attribution merely because a string contains `Mozilla` or `Firefox`.

---

## 25. Branding audit output

Create/maintain a release audit report containing at least:

```text
asset/path
user-visible? yes/no
Mozilla/Firefox brand identity? yes/no
replace? yes/no
Good Bear replacement path
license/owner
status
```

The audit should distinguish:

- trademark/brand assets;
- neutral UI assets;
- license/legal text;
- technical strings and source identifiers.

A plain grep for `Firefox` is not an acceptable rebranding strategy.

---

## 26. Release checklist

Good Bear 1.0 branding is release-ready only when:

- [ ] Application display name is Good Bear.
- [ ] Application icon is an original Good Bear asset.
- [ ] Installer uses Good Bear identity.
- [ ] Desktop/taskbar/Dock launcher uses Good Bear identity.
- [ ] Primary About screen uses Good Bear identity.
- [ ] User-visible Firefox/Mozilla product logos are absent unless used in a legally permitted attribution context.
- [ ] Firefox-specific mascot/illustration branding has been audited and replaced where necessary.
- [ ] Russian PKI Container has a distinct non-government container marker.
- [ ] Russian PKI certificate connections have a separate security badge.
- [ ] Security state is not communicated by mascot or color alone.
- [ ] English/Russian Good Bear-specific strings are localizable.
- [ ] Light/dark/high-contrast modes have been tested.
- [ ] Original brand assets have documented copyright ownership.
- [ ] Required Mozilla attribution/disclaimer appears in Legal/Credits documentation.
- [ ] Government non-affiliation/non-certification disclaimer appears in Legal/Credits documentation.
- [ ] No `®` is used for Good Bear without a valid registration basis.

---

## 27. Open design items

The following require a separate visual-design decision and must not be invented implicitly by Codex:

- final Good Bear logo artwork;
- final mascot artwork;
- final brand color palette;
- final exact Russian PKI badge icon;
- final installer imagery;
- final onboarding illustrations.

Until approved assets exist, implementation should use development placeholders and maintain clean asset injection points.

---

## 28. Canonical ownership notice

For original Good Bear brand materials where appropriate:

```text
Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>
```

This does not replace or alter Mozilla or third-party copyright/license notices.
