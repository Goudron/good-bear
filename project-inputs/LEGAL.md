# Good Bear — юридическая, лицензионная и copyright-политика

**Проект:** Good Bear  
**Версия политики:** 1.0  
**Copyright оригинальных материалов Good Bear:** © 2026 Valery Ledovskoy <valery@ledovskoy.com>  
**Статус:** нормативный документ проекта для исходного кода, сборок, релизов и документации

> Этот документ задаёт правила проекта для Codex и процесса релиза. Он не заменяет индивидуальную юридическую консультацию. Перед публичным/коммерческим релизом необходимо отдельно проверить доступность обозначения **Good Bear** как товарного знака и условия перераспространения сторонних материалов.

---

## 1. Модель copyright

### 1.1. Оригинальные материалы Good Bear

Для оригинальных материалов Good Bear, где это юридически применимо, использовать следующего правообладателя:

```text
Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>
```

К оригинальным материалам Good Bear могут относиться:

- новые исходные файлы Good Bear;
- собственные build/release scripts;
- документация;
- оригинальные строки интерфейса;
- оригинальные графические материалы и mascot artwork;
- иные материалы, созданные специально для Good Bear.

Если файл реально создавался/существенно изменялся в последующие годы, допускается корректный диапазон, например:

```text
Copyright © 2026–2027 Valery Ledovskoy <valery@ledovskoy.com>
```

Не расширять диапазон лет автоматически без фактического основания.

### 1.2. Upstream Firefox/Mozilla

Существующие copyright notices Mozilla, прежних авторов и сторонних правообладателей **нельзя заменять** copyright-строкой Good Bear.

При изменении upstream-файла необходимо:

- сохранить обязательные исходные copyright/license notices;
- сохранить применимую лицензию файла;
- при необходимости добавить корректное уведомление о вкладе Good Bear, не создавая впечатления, что весь upstream-файл написан или принадлежит Valery Ledovskoy;
- не удалять сведения о происхождении кода в процессе rebranding.

### 1.3. Сторонние материалы

Сторонние библиотеки, словари, шрифты, иконки, сертификаты и иные материалы сохраняют собственных правообладателей и собственные лицензии.

Copyright Good Bear распространяется только на собственный вклад Good Bear и не отменяет прав третьих лиц.

---

## 2. Лицензирование исходного кода

### 2.1. Firefox-derived файлы

Firefox-derived файлы продолжают регулироваться применимыми к ним лицензиями, в частности MPL-2.0 там, где она применяется.

Модификации Good Bear в MPL-covered файлах при распространении должны соответствовать MPL-2.0.

### 2.2. Новые программные файлы Good Bear

Если для конкретного файла нет задокументированной причины использовать другую совместимую лицензию, новые программные файлы Good Bear следует лицензировать под MPL-2.0.

Предпочтительный машинно-читаемый идентификатор:

```text
SPDX-License-Identifier: MPL-2.0
```

Вместе с ним для оригинального файла допускается:

```text
Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>
```

Не создавать собственную нестандартную software license без отдельного решения.

### 2.3. Распространение бинарных сборок

При публичном распространении Good Bear, содержащего MPL-covered код, релиз должен давать получателю разумную возможность получить соответствующую Source Code Form, включая применимые модификации Good Bear.

Каждый публичный релиз должен фиксировать:

- точный Good Bear tag/revision;
- точный Firefox upstream tag/revision;
- место получения соответствующего исходного кода/patchset;
- применимую MPL-2.0.

### 2.4. Дополнительные условия для executable form

Условия распространения бинарника не должны ограничивать права получателя на MPL-covered Source Code Form.

Если Good Bear предлагает гарантию, поддержку, indemnity или иные обязательства, должно быть явно указано, что они предоставляются Good Bear / Valery Ledovskoy от собственного имени, а не от имени Mozilla или иных upstream contributors.

---

## 3. Документация и brand assets

### 3.1. Документация

Документация Good Bear должна содержать copyright Good Bear там, где это уместно.

До публичного релиза необходимо явно выбрать и зафиксировать лицензию на независимо созданную документацию. Не считать автоматически, что software license распространяется на любой независимый не-программный материал.

### 3.2. Логотип, mascot и identity assets

Логотип, mascot, application icon и иные оригинальные элементы бренда Good Bear **не становятся автоматически MPL-2.0-licensed только потому, что код браузера распространяется под MPL-2.0**.

Если конкретный asset не содержит иной лицензии, для оригинальных брендовых материалов использовать базовую политику:

```text
Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>
All rights reserved unless otherwise stated.
```

Отдельные artwork-файлы позднее могут получить явно выбранную лицензию.

### 3.3. Заказанный стороннему дизайнеру artwork

Если финальный Good Bear artwork создаёт сторонний дизайнер, до включения в релиз должно существовать письменное основание, обеспечивающее Valery Ledovskoy необходимые права как минимум на:

- использование;
- изменение;
- распространение;
- коммерческое и некоммерческое использование;
- создание производных размеров и состояний;
- использование в качестве product identity и, при необходимости, товарного знака.

Сам факт оплаты работы не следует считать автоматической передачей всех исключительных прав.

---

## 4. Товарные знаки Mozilla и Firefox

Good Bear является модифицированным downstream-браузером. Публичная изменённая сборка не должна представляться как официальная сборка Mozilla Firefox без необходимого письменного разрешения Mozilla.

### 4.1. Собственная product identity

Публичный продукт использует собственное имя:

```text
Good Bear
```

Не использовать как имя/основной бренд продукта:

- Firefox;
- Mozilla Firefox;
- Firefox Good Bear;
- Good Bear Firefox;
- Mozilla;
- официальный Firefox logo;
- официальный Mozilla logo.

### 4.2. Описательное attribution

Названия `Mozilla` и `Firefox` допускаются как правдивое описательное указание происхождения upstream-кода, а не как часть бренда Good Bear.

Базовая формулировка:

```text
Good Bear is an independent browser based on Mozilla Firefox open-source code.
```

### 4.3. Mozilla non-affiliation disclaimer

README, Legal/About и release documentation должны содержать заметное уведомление по смыслу:

```text
Good Bear is an independent project based on Mozilla Firefox open-source code.
Good Bear is not affiliated with, sponsored by, or endorsed by Mozilla.
Mozilla and Firefox are trademarks of the Mozilla Foundation in the United States and other countries.
```

Перед релизом точную формулировку сверить с актуальной Mozilla Trademark Policy.

### 4.4. Не делать производный Good Bear logo из Firefox logo

Запрещено создавать логотип Good Bear путём:

- перекрашивания Firefox logo;
- простой замены животного внутри композиции Firefox;
- трассировки узнаваемого силуэта Firefox logo;
- сохранения сходной flame/orbit-композиции;
- модификации Mozilla logo;
- создания визуально смешиваемой с Firefox официальной вариации.

Good Bear identity должна быть независимо разработана.

---

## 5. Сохранение Mozilla/third-party notices

Rebranding пользовательского интерфейса не означает удаление legal provenance из исходного кода.

Codex обязан:

- не выполнять массовое удаление строк `Mozilla`/`Firefox` из source tree;
- не удалять MPL notices из-за смены product name;
- сохранять необходимые third-party license texts;
- сохранить или адаптировать legal/licenses UI так, чтобы пользователь мог получить применимые open-source notices;
- отличать trademark/brand assets от юридических notices и технических идентификаторов.

---

## 6. Каноническое attribution Good Bear

Для оригинальных Good Bear файлов:

```text
Good Bear
Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>
```

Базовый вариант About/Credits:

```text
Good Bear
Copyright © 2026 Valery Ledovskoy

Based on Mozilla Firefox open-source code.
Good Bear is an independent project and is not affiliated with or endorsed by Mozilla.
See Legal Notices for open-source licenses and third-party attributions.
```

Не заявлять исключительные права на весь Firefox-derived source tree.

---

## 7. Russian PKI / Минцифры / ФСТЭК

Поддержка `Russian Trusted Root CA` не должна создавать впечатление, что Good Bear:

- разработан Минцифры России;
- одобрен Минцифры России;
- сертифицирован Минцифры России;
- одобрен или сертифицирован ФСТЭК России;
- является государственным браузером;
- является сертифицированным СКЗИ только из-за поддержки Russian PKI.

### 7.1. Терминология

Предпочитать технические обозначения:

```text
Russian PKI
Russian Trusted Root CA
Russian PKI trust domain
Russian PKI Container
```

Не использовать официальный государственный герб, логотип Минцифры, ФСТЭК или иные государственные знаки как Good Bear security badge без отдельно подтверждённого правового основания.

### 7.2. Non-affiliation disclaimer

Документация должна содержать уведомление по смыслу:

```text
Support for Russian PKI is an independent Good Bear compatibility and isolation feature.
It does not indicate endorsement, certification or affiliation with the Ministry of Digital Development, FSTEC, or any other government body.
```

---

## 8. Russian PKI certificate material

Техническая подлинность сертификата и право на его перераспространение — разные вопросы.

### 8.1. Техническая подлинность

Production certificate material должен:

- происходить из официального источника;
- быть pinned криптографическими hash/fingerprint;
- иметь manifest с provenance;
- проверяться build/release tooling.

### 8.2. Перераспространение

До коммита production certificate bytes в публичный репозиторий или включения их в бинарный дистрибутив необходимо проверить правовое основание для выбранного способа перераспространения.

Если условия неясны, использовать fail-safe workflow:

- хранить в репозитории официальный source metadata и pinned fingerprints;
- получать/import сертификат из официального источника на контролируемом этапе подготовки/сборки;
- проверять bytes против pinned hash;
- не заменять официальный источник случайной сторонней копией.

Выбранный процесс должен оставаться воспроизводимым и проверяемым.

### 8.3. Не присваивать copyright на certificate data

Не помещать Good Bear copyright внутрь стороннего certificate data и не заявлять ownership на Russian PKI certificates.

---

## 9. Third-party notices

До публичного релиза вести проверяемый inventory сторонних материалов, добавленных Good Bear сверх upstream Firefox.

Минимальные поля:

```text
component / asset
source
version or revision
copyright owner
license
license text location
Good Bear modifications
redistribution status
```

Учитывать, где применимо:

- dictionaries;
- fonts;
- icons;
- artwork;
- source libraries;
- certificate material;
- test fixtures, производные от third-party material.

Для релиза рекомендуется отдельный `THIRD_PARTY_NOTICES.md` или автоматически генерируемый эквивалент.

---

## 10. Hunspell dictionary

При будущем включении пользовательского русского Hunspell-словаря:

- если словарь полностью оригинальный — фиксировать Valery Ledovskoy как правообладателя там, где это юридически применимо;
- если использовался существующий словарь/корпус/база — сохранить и выполнить его лицензионные и attribution requirements;
- не называть производные данные полностью оригинальными, если это не так;
- включить dictionary license/attribution в release notices.

Само встраивание Hunspell не входит в Russian PKI implementation task, но подчиняется настоящей legal policy.

---

## 11. Codex и внешние исходники

Codex должен использовать project copyright notice для оригинальных Good Bear файлов там, где это предусмотрено, но не должен:

- удалять third-party notices;
- заявлять ownership Valery Ledovskoy на upstream Mozilla code;
- придумывать отсутствующую лицензию стороннего материала;
- копировать существенный код или artwork из публичного источника без проверки license compatibility;
- считать доступность кода в интернете разрешением на его включение в Good Bear.

При импорте/адаптации внешнего кода фиксировать provenance и license до merge.

---

## 12. Проверка названия Good Bear

Настоящий документ фиксирует `Good Bear` как рабочее/планируемое имя проекта, но не является заключением о доступности товарного знака.

Перед существенным публичным или коммерческим запуском:

- выполнить поиск по релевантным классам ПО/IT и целевым юрисдикциям;
- проверить сходные названия software/services;
- решить вопрос подачи заявки на товарный знак;
- не использовать `®` без действующего основания;
- не добавлять `™` автоматически без отдельного brand/legal решения.

---

## 13. Release-blocking legal checklist

Публичный Good Bear 1.0 нельзя считать готовым к релизу, пока:

- [ ] Product name и product identity — Good Bear, а не Firefox/Mozilla branding.
- [ ] Официальные Firefox/Mozilla logos отсутствуют в Good Bear product identity.
- [ ] Upstream copyright/license notices сохранены.
- [ ] Corresponding MPL-covered source доступен для бинарного релиза.
- [ ] Оригинальные Good Bear source files используют `Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>` там, где применимо.
- [ ] Good Bear original brand assets имеют документированного правообладателя и license status.
- [ ] Third-party assets имеют документированные licenses/notices.
- [ ] Russian PKI certificate material имеет официальный provenance и проверенный redistribution workflow.
- [ ] Mozilla/Firefox attribution носит описательный характер.
- [ ] Mozilla non-affiliation disclaimer присутствует.
- [ ] Government/Ministry/FSTEC non-affiliation/non-certification disclaimer присутствует.
- [ ] Legal/About UI предоставляет необходимые open-source/third-party notices.
- [ ] Нет UI-текста, представляющего Good Bear официальным Mozilla или государственным продуктом.
- [ ] Нет заявления о certified SKZI/GOST support в Good Bear 1.0.

---

## 14. Авторитетные источники, которые нужно перепроверять перед релизом

Mozilla Public License 2.0:  
https://www.mozilla.org/MPL/2.0/

Mozilla MPL 2.0 FAQ:  
https://www.mozilla.org/MPL/2.0/FAQ/

Mozilla Trademark Guidelines:  
https://www.mozilla.org/foundation/trademarks/policy/

Mozilla Software Distribution Policy:  
https://www.mozilla.org/foundation/trademarks/distribution-policy/

Политики могут изменяться. Перед значимым публичным релизом сверять актуальные версии с официальными источниками.

---

## 15. Каноническая copyright-строка Good Bear 1.0

Для оригинального материала Good Bear, где это уместно:

```text
Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>
```

Эта строка **никогда не должна использоваться для замены или подавления существующего copyright notice Mozilla или иного третьего лица**.
