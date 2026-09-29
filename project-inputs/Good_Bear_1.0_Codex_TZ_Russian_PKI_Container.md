# Техническое задание для Codex

## Good Bear 1.0 — изолированная поддержка сайтов с цепочкой Russian Trusted Root CA

**Статус:** draft / implementation specification  
**Целевая кодовая база:** desktop Firefox / Gecko, актуальная стабильная ветка на момент начала разработки  
**Проект:** Good Bear  
**Версия:** 1.0  
**Copyright оригинальных материалов Good Bear:** © 2026 Valery Ledovskoy <valery@ledovskoy.com>  
**Legal policy:** `LEGAL.md`  
**Brandbook:** `BRANDING.md`  
**Язык документа:** русский  
**Назначение:** прямое ТЗ для Codex на исследование, реализацию, тестирование и документирование функциональности Russian PKI Container.

---

## 1. Цель версии

Реализовать в Good Bear поддержку HTTPS-сайтов, сертификатная цепочка которых успешно проверяется до официального `Russian Trusted Root CA`, **без глобального добавления этого корневого сертификата в обычную область доверия браузера**.

Такие сайты должны работать только в специальном встроенном контейнере Good Bear — **Russian PKI Container**.

Основные принципы:

1. обычные вкладки Good Bear используют штатную модель доверия Firefox;
2. `Russian Trusted Root CA` не является глобально доверенным корнем;
3. если сайт не проходит стандартную проверку Firefox, но полностью и корректно проходит альтернативную проверку до известного `Russian Trusted Root CA`, Good Bear классифицирует соединение как `RUSSIAN_PKI`;
4. такой сайт разрешается открывать только в специальном контейнере;
5. cookies, storage, login/autofill state и иные данные стандартного контекста не должны автоматически передаваться сайту, который требует Russian PKI trust domain;
6. браузер должен явно показывать пользователю одновременно, что вкладка находится в специальном контейнере и используется ли для текущего соединения Russian PKI или стандартная PKI;
7. российские криптографические алгоритмы в версии 1.0 **не реализуются**.

---

## 2. Ожидаемое пользовательское поведение

### 2.1. Обычный HTTPS-сайт

Если цепочка сертификата проходит штатную проверку Firefox:

- сайт открывается в обычной вкладке;
- Russian PKI Container не задействуется;
- дополнительной индикации Russian PKI нет;
- поведение должно максимально совпадать с upstream Firefox.

### 2.2. Сайт с корректной цепочкой Russian Trusted Root CA

При открытии в обычной вкладке сайта, сертификат которого, например, выдан `Russian Trusted Sub CA` и ведёт к `Russian Trusted Root CA`, Good Bear должен:

1. выполнить обычную проверку сертификата;
2. если обычная проверка завершается из-за отсутствия доверенного anchor, выполнить вторичную проверку против встроенного набора Russian PKI trust anchors;
3. если вторичная проверка полностью успешна:
   - не отправлять HTTP-данные обычного контейнера этому соединению;
   - остановить текущую навигацию;
   - открыть URL в Russian PKI Container;
   - повторить навигацию уже с `userContextId` специального контейнера;
4. в Russian PKI Container разрешить цепочку Russian PKI;
5. показать специальную индикацию.

Ожидаемая схема:

```text
Russian PKI Container
        ↓
https://fstec.ru
        ↓
Russian Trusted Sub CA
        ↓
Russian Trusted Root CA
        ↓
VALID
```

Для корректной Russian PKI цепочки `SEC_ERROR_UNKNOWN_ISSUER` после переноса в контейнер возникать не должен.

---

## 3. Принципиальная модель безопасности

Good Bear не должен считать Russian PKI эквивалентом стандартного Mozilla/Firefox trust domain.

Внутри реализации должны существовать как минимум следующие логические состояния:

```text
STANDARD
RUSSIAN_PKI
INVALID
```

### 3.1. STANDARD

Соединение прошло штатную проверку сертификата Firefox без использования специальных trust anchors Good Bear.

### 3.2. RUSSIAN_PKI

Стандартная проверка не смогла построить доверенную цепочку, но вторичная проверка Good Bear успешно построила и проверила цепочку до **точно известного** Russian PKI trust anchor.

### 3.3. INVALID

Сертификат не проходит ни стандартную, ни Russian PKI проверку либо нарушает любое обязательное правило X.509/TLS.

---

## 4. Неприкосновенные security invariants

Следующие требования обязательны и не могут быть упрощены ради ускорения разработки.

### 4.1. Russian Trusted Root CA не должен становиться глобально доверенным

Запрещено решать задачу простым глобальным импортом Russian Trusted Root CA в основной root store так, чтобы он работал во всех `userContextId`.

Корень Russian PKI должен быть применим только в рамках специальной scoped policy Good Bear.

### 4.2. Запрещена идентификация Russian PKI по строковым полям

Нельзя определять Russian PKI по:

- `CN`;
- `O`;
- `OU`;
- issuer name;
- subject name;
- наличию слова `Russian`;
- имени `Russian Trusted Root CA`;
- имени `Russian Trusted Sub CA`.

Решение о trust domain должно основываться на криптографически проверенной цепочке и точном доверенном anchor.

Минимальный идентификатор trust anchor:

- SHA-256 fingerprint полного сертификата.

Дополнительно допускается хранить SHA-256 SPKI, serial, subject и validity period, но эти значения не заменяют проверку точного trust anchor.

### 4.3. Нельзя ослаблять стандартную проверку сертификата

Russian PKI Container не должен игнорировать:

- неправильный hostname;
- истёкший сертификат;
- сертификат, ещё не вступивший в силу;
- неверную цифровую подпись;
- неподходящий EKU/Key Usage;
- неправильные Basic Constraints;
- path length violations;
- недопустимую цепочку;
- иные штатные ошибки certificate validation Firefox.

Разница между STANDARD и RUSSIAN_PKI заключается **только в разрешённом trust anchor**.

### 4.4. Russian Trusted Sub CA не является trust anchor

Если промежуточный сертификат Russian Trusted Sub CA поставляется вместе с Good Bear, он используется только как intermediate.

Запрещено помечать intermediate как самостоятельно доверенный root.

### 4.5. Никаких универсальных исключений

Нельзя:

- автоматически принимать self-signed сертификаты;
- превращать `SEC_ERROR_UNKNOWN_ISSUER` в общий success;
- отключать certificate verification;
- отключать hostname verification;
- добавлять универсальное пользовательское исключение для всех российских сертификатов.

---

## 5. Сертификатные материалы

В репозитории должен быть создан отдельный управляемый набор Russian PKI материалов.

Рекомендуемая структура:

```text
goodbear/
└── russian-pki/
    ├── roots/
    │   └── russian-trusted-root-ca.der
    ├── intermediates/
    │   └── russian-trusted-sub-ca.der
    ├── manifest.json
    ├── README.md
    └── verify-certificates.py
```

Фактическое расположение можно изменить после анализа дерева Firefox, но материалы Good Bear желательно держать отдельно от upstream-ресурсов.

### 5.1. Источник сертификатов

Сертификаты должны быть получены из официального государственного источника.

Codex не должен:

- брать root из случайного GitHub-репозитория;
- брать root из стороннего блога;
- копировать fingerprint из непроверенной статьи;
- доверять сертификату только потому, что имя совпадает.

В `manifest.json` необходимо хранить минимум:

```json
{
  "role": "root",
  "sha256": "...",
  "spki_sha256": "...",
  "serial": "...",
  "subject": "...",
  "not_before": "...",
  "not_after": "...",
  "official_source": "...",
  "retrieved_at": "..."
}
```

### 5.2. Проверка сборки

Сборка должна падать, если:

- DER-файл не соответствует указанному SHA-256;
- manifest повреждён;
- роль сертификата не соответствует ожидаемой;
- root был незаметно заменён другим сертификатом.

### 5.3. Ротация сертификатов

Архитектура должна допускать несколько Russian PKI trust anchors, но каждый новый anchor должен добавляться явным изменением исходного кода/manifest и проходить code review.

В Good Bear 1.0 не требуется механизм удалённого динамического обновления Russian PKI root store.

---

## 6. Алгоритм проверки сертификата

### 6.1. Обычная вкладка

```text
standard Firefox verification
        │
        ├── success
        │      ↓
        │   STANDARD
        │
        └── failure
               ↓
     secondary Russian PKI verification
               │
               ├── full success
               │      ↓
               │   RUSSIAN_PKI_REQUIRED
               │
               └── failure
                      ↓
                original/most relevant TLS error
```

Вторичная Russian PKI проверка не должна превращать текущий ordinary channel в доверенный. Она используется для классификации и безопасного переноса top-level navigation в специальный контейнер.

### 6.2. Russian PKI Container

Для соединения, чей `OriginAttributes.userContextId` соответствует Russian PKI Container:

```text
standard Firefox verification
        │
        ├── success
        │      ↓
        │   STANDARD
        │
        └── failure caused by missing trust anchor
               ↓
     Russian PKI verification
               │
               ├── full success
               │      ↓
               │   RUSSIAN_PKI
               │
               └── failure
                      ↓
                    TLS error
```

### 6.3. Приоритет STANDARD

Если сертификат успешно проходит обычную проверку Firefox, соединение считается `STANDARD`.

Не нужно принудительно искать альтернативную Russian PKI цепочку, если стандартная цепочка уже валидна.

### 6.4. Результат должен быть доступен UI и routing layer

Нужно предоставить устойчивый признак:

```text
trustDomain = STANDARD | RUSSIAN_PKI | INVALID
```

UI не должен повторно угадывать тип цепочки по `issuer` или другим строкам сертификата.

---

## 7. Russian PKI Container

Good Bear должен использовать встроенную Firefox/Gecko инфраструктуру контейнеров (`userContextId` / `OriginAttributes`), а не WebExtension.

### 7.1. Системный контейнер

Создать встроенный контейнер со стабильным внутренним назначением:

```text
goodbear-russian-pki
```

Пользовательское имя:

```text
Russian PKI
```

или локализованное:

```text
Российская PKI
```

### 7.2. Контейнер управляется Good Bear

Пока Russian PKI support включён:

- контейнер не должен случайно исчезать;
- его удаление через обычный UI не должно ломать trust policy;
- при необходимости он должен пересоздаваться;
- нельзя молча перенести Russian PKI trust в обычный контейнер из-за отсутствия специального контейнера.

Если пользователь полностью отключает функциональность Russian PKI, Russian Trusted Root CA не должен становиться доверенным нигде.

### 7.3. Реальный `userContextId`

Нельзя эмулировать контейнер:

- отдельным окном без `userContextId`;
- только цветом вкладки;
- только preference-флагом;
- JavaScript-флагом страницы.

Должна использоваться настоящая container isolation инфраструктура Firefox.

---

## 8. Автоматическое открытие Russian PKI сайтов

### 8.1. Первый визит

Если пользователь впервые открывает URL в обычной вкладке и:

- стандартная валидация не проходит;
- Russian PKI валидация полностью проходит;

Good Bear должен автоматически открыть этот URL в Russian PKI Container.

Для обычного GET/HEAD top-level navigation не требуется отдельное подтверждение, если отсутствует конфликт с trust history.

### 8.2. Перенос вкладки

Допустимо:

1. создать новую вкладку в Russian PKI Container;
2. перенести URL;
3. сделать новую вкладку активной;
4. закрыть техническую старую вкладку после запуска новой навигации.

При этом запрещено переносить из старого контекста:

- cookies;
- DOM;
- JS state;
- `window.opener`;
- form state;
- session storage;
- POST body;
- authentication headers.

### 8.3. Referrer

При автоматическом переносе ordinary → Russian PKI необходимо по умолчанию **не переносить Referer** от ordinary page.

Container migration считается privacy boundary.

### 8.4. POST и другие body-carrying запросы

Good Bear не должен автоматически повторять POST/PUT/PATCH или другую навигацию с телом после смены контейнера.

При обнаружении необходимости Russian PKI Container:

- ordinary request должен быть остановлен до передачи HTTP body;
- пользователь получает специальный interstitial;
- браузер не повторяет body автоматически в новом контейнере.

Допустимый UX:

```text
Этот адрес требует Russian PKI Container.
Запрос содержит данные и не может быть автоматически повторён
при смене контейнера.

[Открыть сайт в Russian PKI] [Назад]
```

### 8.5. Redirect

Если STANDARD-сайт возвращает redirect на Russian PKI endpoint:

- первый STANDARD HTTP response допустим;
- дальнейшая навигация классифицируется отдельно;
- Russian endpoint открывается в Russian PKI Container;
- ordinary cookies/state не переносятся;
- referrer через границу контейнеров удаляется.

---

## 9. Sticky behavior

Russian PKI Container должен быть «липким».

Если вкладка уже находится в Russian PKI Container, последующие top-level переходы внутри этой вкладки остаются в том же контейнере, даже если следующий сайт использует обычную STANDARD PKI.

```text
Russian PKI tab
    fstec.ru
        ↓
    example.com
        ↓
    wikipedia.org
```

Все сайты остаются в том же `userContextId`, пока пользователь явно не откроет ссылку в обычной вкладке.

### 9.1. Нельзя автоматически возвращать вкладку в ordinary context

Запрещено:

```text
RUSSIAN_PKI certificate → Russian container
STANDARD certificate     → auto-move back to ordinary
```

### 9.2. `window.open` и новые вкладки

Страницы внутри Russian PKI Container должны по возможности создавать новые вкладки/окна в том же `userContextId`, если пользователь явно не выбрал другой контекст.

---

## 10. Persistent site assignment

После того как origin подтверждён как Russian PKI, Good Bear должен запомнить его как сайт, связанный с Russian PKI Container.

Рекомендуемый ключ:

```text
scheme + host + effective port
```

Например:

```text
https://fstec.ru:443
```

### 10.1. Повторный визит

Для известного Russian PKI origin:

- Good Bear сразу отправляет пользователя в Russian PKI Container;
- ordinary network request к origin по возможности не выполняется.

### 10.2. Хранение

Список должен:

- храниться локально в профиле;
- не синхронизироваться через Firefox Sync в 1.0;
- иметь возможность очистки;
- не содержать cookies или credentials;
- содержать только routing/trust metadata.

### 10.3. Subdomains

Назначение выполняется по конкретному origin/host.

Нельзя автоматически считать все субдомены Russian PKI только потому, что один субдомен использовал эту цепочку.

---

## 11. Trust history и смена trust domain

Это обязательная функция Good Bear 1.0.

Нужно хранить минимальную историю наблюдаемого trust domain для origin.

### 11.1. Первый визит Russian PKI

Если origin ранее неизвестен и впервые валидируется как Russian PKI:

- допускается автоматическое открытие в Russian PKI Container;
- origin записывается в assignment list;
- можно показать неблокирующее информационное сообщение.

### 11.2. STANDARD → RUSSIAN_PKI

Если origin ранее успешно открывался как `STANDARD`, а теперь валидируется как `RUSSIAN_PKI`, автоматическое продолжение запрещено.

Нужно показать blocking interstitial:

```text
Источник доверия сайта изменился

Ранее этот сайт использовал стандартную инфраструктуру доверия.
Сейчас сертификат проверяется через Russian PKI.

Good Bear не будет передавать этому соединению данные
обычного контейнера.

[Открыть изолированно] [Назад]
```

После выбора «Открыть изолированно»:

- origin получает persistent Russian PKI assignment;
- открывается Russian PKI Container;
- ordinary site state не переносится.

### 11.3. RUSSIAN_PKI → STANDARD

Если origin уже закреплён за Russian PKI Container, он должен продолжать открываться в этом контейнере даже после перехода на стандартный сертификат, пока пользователь явно не сбросит назначение.

### 11.4. Управление списком

Нужно предусмотреть возможность:

- посмотреть закреплённые сайты;
- удалить один origin;
- очистить весь список.

---

## 12. Subresources и embedded content

Нельзя пытаться переносить отдельный iframe/script/image в другой контейнер внутри ordinary page.

### 12.1. Russian PKI subresource внутри STANDARD page

Если ordinary page пытается загрузить через Russian PKI:

- script;
- image;
- CSS;
- XHR/fetch;
- iframe;
- media;
- WebSocket;
- другой subresource,

Good Bear должен **заблокировать этот subresource** в ordinary context.

Нельзя:

- доверять Russian Root ради subresource;
- отправлять ordinary cookies;
- создавать скрытый Russian container request и возвращать результат ordinary page.

### 12.2. Диагностика

В browser console/devtools выводить понятное сообщение, например:

```text
Good Bear blocked a Russian PKI resource in the standard context.
Open the top-level site in the Russian PKI container if needed.
```

### 12.3. Внутри Russian PKI Container

Разрешяются:

- STANDARD subresources;
- корректные RUSSIAN_PKI subresources;

при сохранении одного `userContextId`.

---

## 13. Изоляция browser state

Russian PKI Container должен использовать штатную container isolation Firefox как минимум для:

- cookies;
- localStorage;
- IndexedDB;
- Cache API;
- service workers;
- origin storage;
- другой state, штатно partitioned по `userContextId`.

Codex должен подтвердить тестами, какие компоненты действительно разделены текущей версией Firefox.

Нельзя заявлять «полная изоляция браузера», если конкретный тип state остаётся глобальным.

---

## 14. Password Manager и autofill

Обычная container isolation Firefox не должна считаться достаточной для credential isolation.

### 14.1. Password autofill

В Russian PKI Container по умолчанию отключить автоматическое предложение/подстановку логинов и паролей из общего password store.

Особенно запрещено автоматически подставлять credentials, сохранённые для того же origin в ordinary context.

### 14.2. Сохранение паролей

Для версии 1.0 предпочтительное поведение:

- не сохранять Russian PKI credentials в общий глобальный password store;
- не показывать стандартное предложение сохранения, если оно приводит к смешению credential domains.

Если отдельный container-aware password store слишком велик для 1.0, сохранение паролей в Russian PKI Container отключается.

### 14.3. Address/payment autofill

Если Firefox использует глобальные сохранённые адреса, платёжные данные или другие чувствительные autofill records, Good Bear не должен автоматически подставлять их в Russian PKI Container.

---

## 15. HTTP authentication и другие credential caches

Codex должен исследовать:

- HTTP Basic/Digest auth cache;
- TLS client auth state, если применимо;
- cached credentials;
- connection authentication state.

Russian PKI Container не должен автоматически использовать authentication state ordinary context.

Если текущий Firefox уже partitioned по OriginAttributes, это подтвердить тестом. Если какой-то credential cache глобален, его нужно либо разделить, либо отключить reuse в Russian PKI Container.

---

## 16. TLS 0-RTT / Early Data

До определения trust domain Good Bear не должен передавать HTTP application data соединению, которое впоследствии окажется Russian PKI.

На первом этапе допустима консервативная реализация:

- отключить TLS 1.3 0-RTT/Early Data для Good Bear целиком; либо
- гарантированно отключать его для origin, чей trust domain не установлен заранее.

Codex должен сначала исследовать текущую реализацию Firefox/NSS и зафиксировать решение в design note.

Обязательный инвариант:

```text
unknown trust domain
        ↓
no early HTTP data
        ↓
certificate classification
        ↓
STANDARD or RUSSIAN_PKI
        ↓
only then application data
```

Оптимизация 0-RTT не имеет приоритета перед изоляцией.

---

## 17. Пользовательский интерфейс

Нужно различать два независимых факта:

1. вкладка находится в Russian PKI Container;
2. текущее соединение реально использует Russian PKI trust chain.

### 17.1. Индикация контейнера

Russian PKI tab должна иметь постоянную визуальную маркировку контейнера.

Пример:

```text
[Russian PKI] fstec.ru
```

или компактный shield/badge.

### 17.2. Индикация trust chain

Если:

```text
trustDomain = RUSSIAN_PKI
```

в address bar отображается отдельный индикатор, например:

```text
RU CA
```

### 17.3. STANDARD сайт внутри Russian PKI Container

Если пользователь в уже изолированной вкладке перешёл на STANDARD-сайт:

- container marker остаётся;
- Russian PKI certificate badge не показывается;
- UI может сообщать: «Вкладка остаётся изолированной; текущий сайт использует стандартную цепочку доверия».

Не путать `container identity` и `certificate trust source`.

### 17.4. Security popup

При клике на Russian PKI badge показывать минимум:

- статус защищённого соединения;
- hostname;
- leaf certificate subject;
- issuer;
- root/trust anchor;
- `trust source = Good Bear Russian PKI`;
- пояснение, что anchor разрешён только в Russian PKI Container;
- кнопку просмотра сертификата.

Не использовать формулировки, создающие впечатление, что Good Bear является официальным продуктом Минцифры.

---

## 18. Страница смены trust domain

Для `STANDARD → RUSSIAN_PKI` создать отдельный interstitial, а не использовать обычный `SEC_ERROR_UNKNOWN_ISSUER`.

Обязательные элементы:

- понятное название проблемы;
- пояснение, что сертификат может быть валиден, но используется другой trust domain;
- пояснение, что ordinary browsing data не будет передана;
- кнопка `Открыть изолированно`;
- кнопка `Назад`;
- возможность посмотреть сертификат.

Запрещена формулировка «Сайт безопасен».

Предпочтительно:

```text
Сертификат успешно проверяется через Russian PKI,
но Good Bear изолирует такую инфраструктуру доверия
от стандартного контекста.
```

---

## 19. Поведение при ошибках

### 19.1. Не Russian PKI

Если secondary Russian PKI verification неуспешна, показывать стандартную ошибку Firefox.

### 19.2. Неправильный hostname

Не открывать в контейнере. Показывать штатную hostname error.

### 19.3. Просроченный сертификат

Не открывать в контейнере.

### 19.4. Поддельный root с тем же CN

Не открывать в контейнере.

### 19.5. Повреждённая подпись

Не открывать.

### 19.6. Отсутствующий intermediate

Если Good Bear поставляет официальный intermediate локально, допускается использовать его для построения цепочки, но intermediate не становится trust anchor.

---

## 20. Private Browsing

Codex должен исследовать, можно ли в текущей версии Firefox безопасно совмещать:

```text
privateBrowsingId
+
userContextId
```

Предпочтительный вариант — Russian PKI semantics работает и в Private Browsing без смешения state.

Если это требует крупного и рискованного изменения, Good Bear 1.0 должен:

- заблокировать Russian PKI trust в Private Browsing;
- предложить открыть сайт в обычном Russian PKI Container;
- **не** делать Russian Root глобально доверенным ради Private Browsing.

Безопасный отказ предпочтительнее обхода isolation model.

---

## 21. Настройки Good Bear

Минимально нужны настройки:

### Russian PKI support

```text
[✓] Включить поддержку Russian PKI
```

При отключении:

- Russian Root не доверяется нигде;
- persistent assignments не используются для trust;
- сайты получают стандартное поведение Firefox.

### Russian PKI sites

Пользователь может:

- увидеть список назначенных origin;
- удалить один origin;
- очистить список.

### Credentials

Показать, что password/autofill isolation включена. Если отдельное хранилище паролей не реализовано, UI должен честно указывать, что сохранение/автоподстановка отключены в этом контейнере.

---

## 22. Что контейнер НЕ обещает

Документация и UI Good Bear не должны утверждать, что Russian PKI Container делает пользователя анонимным или предотвращает любое наблюдение.

Контейнер **не скрывает автоматически**:

- IP-адрес;
- факт соединения с сервером;
- сетевой маршрут;
- DNS, если отдельно не используется защищённая DNS-конфигурация;
- TLS/browser fingerprint;
- данные, которые пользователь сам отправляет сайту;
- содержимое соединения от конечного сервера;
- содержимое от активного MITM, если его сертификат успешно принят внутри Russian PKI trust domain.

Корректное позиционирование:

> Russian PKI Container изолирует браузерную идентичность и локальное состояние от стандартного контекста при работе с отдельной инфраструктурой доверия.

---

## 23. WebExtensions

Версия 1.0 не должна реализовываться как расширение.

Установленные пользователем расширения с широкими permissions потенциально могут иметь доступ к нескольким контейнерам и уменьшать степень изоляции.

В threat model указать:

- container isolation не является sandbox против привилегированных browser extensions;
- Good Bear не гарантирует разделение данных от расширения, которому пользователь дал необходимые host/data permissions.

Отдельная permission model расширений в 1.0 не требуется.

---

## 24. Российская криптография — вне scope

В Good Bear 1.0 запрещено реализовывать или интегрировать:

- ГОСТ Р 34.10-2012;
- ГОСТ Р 34.11-2012 / Стрибог;
- Кузнечик;
- Магма;
- GOST TLS cipher suites;
- GOST TLS 1.2;
- GOST TLS 1.3;
- CryptoPro CSP integration;
- GOST OpenSSL Engine;
- специальные GOST PKCS#11 механизмы;
- CMS/CAdES ГОСТ;
- электронную подпись;
- собственный WebCrypto GOST API.

Нельзя расширять TLS cipher suite list ради этой задачи.

Версия 1.0 работает только с криптографическими алгоритмами, уже поддерживаемыми текущим Firefox/NSS.

---

## 25. Другие функции Good Bear и границы текущей задачи

Основная инженерная задача данного ТЗ — Russian PKI Container и связанная с ним модель доверия/изоляции.

Следующие функции требуют отдельных implementation tasks:

- производство финального Good Bear artwork и полного набора изображений «доброго медведя»;
- встроенный русский Hunspell-словарь;
- GOST cryptography;
- электронная подпись;
- собственная update infrastructure.

При этом **legal/rebranding compliance является обязательным release gate для публичного Good Bear 1.0**. Публичная модифицированная сборка не должна распространяться под официальным Firefox/Mozilla product branding без необходимых разрешений.

Нормативные требования к лицензиям, copyright и attribution определены в `LEGAL.md`.

Нормативные требования к имени, визуальной идентичности, замене Firefox-specific artwork, Russian PKI badge и разделению brand/security semantics определены в `BRANDING.md`.

До появления финального оригинального artwork Codex должен создавать чистые точки подключения ресурсов и использовать только явно помеченные development placeholders, а не производные от Firefox logo/artwork.

---

## 26. Требования к архитектуре патчей

Изменения должны быть локальными и удобными для rebase на новые версии Firefox.

Желательное разделение commits/patches:

```text
01-goodbear-russian-pki-cert-assets
02-goodbear-russian-pki-trust-domain
03-goodbear-russian-pki-container
04-goodbear-russian-pki-routing
05-goodbear-russian-pki-trust-history
06-goodbear-russian-pki-credential-isolation
07-goodbear-russian-pki-ui
08-goodbear-russian-pki-tests
09-goodbear-russian-pki-docs
```

Нельзя делать один огромный неделимый patch.

---

## 27. Этап 0: обязательное исследование до изменения кода

Codex не должен сразу начинать модифицировать NSS/PSM.

Сначала создать:

```text
docs/goodbear-russian-pki-design.md
```

В нём зафиксировать:

1. актуальную версию/commit Firefox;
2. путь стандартной certificate verification;
3. где доступен `OriginAttributes.userContextId`;
4. где хранится/передаётся `nsITransportSecurityInfo`;
5. где лучше разместить secondary trust-domain verification;
6. как передать `trustDomain` до browser UI;
7. как Firefox создаёт и сохраняет built-in containers;
8. как перезапустить top-level navigation в другом `userContextId`;
9. как предотвратить перенос referrer/opener/body;
10. как ведёт себя 0-RTT;
11. partitioning password manager и HTTP auth;
12. ограничения Private Browsing;
13. список upstream-файлов, которые планируется изменить.

Только после этого переходить к реализации.

Если предпосылка ТЗ неверна для актуальной ветки Firefox, не обходить её небезопасным способом. Зафиксировать проблему и предложить безопасную альтернативу.

---

## 28. Предпочтительный внутренний API

Желательно иметь один нормализованный тип:

```cpp
enum class GoodBearTrustDomain {
  Standard,
  RussianPKI,
  Invalid
};
```

или эквивалент.

Не размазывать определения вроде `isRussianCA`, `isMincifry`, `isRuCert`, `specialRoot` по UI и networking code.

Должен быть один источник истины.

---

## 29. Тестовые сертификаты

Автоматические тесты не должны зависеть от доступности живых государственных сайтов.

Создать локальные fixtures.

### Test Standard CA

Обычная локальная тестовая PKI Firefox.

### Test Russian PKI

```text
Test Russian Root
    ↓
Test Russian Intermediate
    ↓
test-russian.example
```

Для test root использовать тот же code path, что и для production Russian PKI manifest, но отдельный test-only trust anchor.

Отрицательные fixtures:

- fake root с тем же subject;
- expired leaf;
- wrong hostname;
- bad signature;
- invalid intermediate;
- wrong EKU.

---

## 30. Обязательные автоматические сценарии

### T01 — STANDARD в ordinary context

**Given:** валидный стандартный сертификат  
**When:** пользователь открывает сайт  
**Then:** сайт остаётся в ordinary context  
**And:** `trustDomain = STANDARD`.

### T02 — Russian PKI first visit

**Given:** origin неизвестен  
**And:** стандартная проверка даёт unknown/untrusted issuer  
**And:** Russian PKI secondary verification полностью успешна  
**When:** пользователь открывает GET URL  
**Then:** ordinary navigation прекращается  
**And:** URL открывается в Russian PKI Container  
**And:** `trustDomain = RUSSIAN_PKI`  
**And:** origin записывается в assignment list.

### T03 — known Russian PKI origin

**Given:** origin назначен Russian PKI  
**When:** пользователь вводит URL в ordinary window  
**Then:** навигация сразу создаётся в Russian PKI Container  
**And:** ordinary network request к origin по возможности не выполняется.

### T04 — fake Russian CA name

**Given:** сертификат имеет те же CN/O строки  
**But:** root fingerprint другой  
**Then:** сайт не классифицируется как RUSSIAN_PKI.

### T05 — wrong hostname

**Given:** chain заканчивается на правильном Russian Root  
**But:** hostname invalid  
**Then:** сайт не открывается  
**And:** container migration не выполняется.

### T06 — expired certificate

Обычная TLS error, без container migration.

### T07 — bad signature

Обычная TLS error, без container migration.

### T08 — STANDARD → RUSSIAN_PKI

**Given:** origin ранее был STANDARD  
**When:** теперь chain = RUSSIAN_PKI  
**Then:** показывается blocking trust-change interstitial  
**And:** ordinary cookies/body не отправляются  
**And:** auto-open запрещён до явного подтверждения.

### T09 — RUSSIAN_PKI → STANDARD

**Given:** origin назначен Russian PKI  
**And:** текущий сертификат теперь STANDARD  
**Then:** origin продолжает открываться в Russian PKI Container  
**Until:** пользователь удалит assignment.

### T10 — sticky navigation

**Given:** Russian PKI Container  
**When:** пользователь переходит на STANDARD site  
**Then:** вкладка остаётся в Russian PKI Container.

### T11 — cookie isolation

Cookie ordinary context не видна той же origin identity в Russian PKI Container и наоборот.

### T12 — localStorage isolation

Аналогично.

### T13 — IndexedDB isolation

Аналогично.

### T14 — service worker isolation

Service worker ordinary context не должен управлять Russian PKI context.

### T15 — password autofill isolation

Saved login ordinary context не должен автоматически подставляться в Russian PKI Container.

### T16 — POST migration

POST не должен автоматически повторяться после обнаружения Russian PKI requirement.

### T17 — referrer

Automatic ordinary → Russian PKI transfer не переносит referrer ordinary page.

### T18 — opener

Russian PKI tab, созданная из ordinary context, не получает живой `window.opener`, пересекающий boundary.

### T19 — subresource

Russian PKI subresource в ordinary page блокируется.

### T20 — standard subresource in Russian container

STANDARD subresource внутри Russian PKI page разрешён в том же `userContextId`.

### T21 — disabled feature

При отключённой Russian PKI support корректная Russian chain не становится глобально доверенной.

### T22 — intermediate is not root

Если chain не доходит до точного Russian trust anchor, соединение не принимается.

### T23 — session restore

После перезапуска Russian PKI tab восстанавливается в правильном `userContextId`.

### T24 — assignment persistence

Список Russian PKI origin сохраняется после restart.

### T25 — 0-RTT invariant

Ни cookies, ни HTTP headers/body ordinary context не передаются как early data соединению, классифицированному впоследствии как Russian PKI.

---

## 31. Ручные smoke tests

После автоматических тестов выполнить ручную проверку на реальном актуальном сайте с Russian PKI chain.

На момент подготовки ТЗ примером является:

```text
https://fstec.ru/
```

Автоматические тесты не должны зависеть от этого сайта: его сертификаты и инфраструктура могут измениться.

Smoke test успешен, если:

1. используется чистый профиль Good Bear;
2. URL вводится обычным способом;
3. браузер обнаруживает Russian PKI;
4. сайт открывается в специальном контейнере;
5. `SEC_ERROR_UNKNOWN_ISSUER` отсутствует;
6. отображается Russian PKI badge;
7. ordinary cookies не попадают в контейнер;
8. просмотр сертификата показывает реальную проверенную цепочку.

---

## 32. Telemetry и network calls

Функция не должна добавлять новый сервер Good Bear и не должна отправлять наружу:

- список Russian PKI сайтов;
- trust history;
- fingerprints посещённых leaf certificates;
- container assignments.

Если upstream Firefox telemetry присутствует, это отдельный вопрос и данным ТЗ не изменяется.

---

## 33. Логирование

Добавить debug logging, включаемый dev-pref или logging module.

Допустимые сообщения:

```text
GoodBearTrust: standard verification failed
GoodBearTrust: Russian PKI secondary verification succeeded
GoodBearRouting: reopening origin in Russian PKI container
GoodBearTrustHistory: STANDARD -> RUSSIAN_PKI
```

Не логировать:

- пароли;
- form data;
- cookies;
- authorization headers;
- private keys.

---

## 34. Производительность

Secondary Russian PKI verification не должна выполняться для каждого успешного STANDARD HTTPS соединения.

```text
STANDARD verification success
        ↓
stop
```

Secondary verification запускается только когда стандартная проверка не смогла получить доверенный anchor либо в другом строго обоснованном случае.

Для уже назначенных Russian PKI origins можно сразу использовать Russian PKI Container.

---

## 35. Совместимость

Решение должно быть реализовано на уровне общей desktop кодовой базы Firefox и без необходимости не привязываться к конкретной ОС.

Целевые платформы:

- Linux;
- Windows;
- macOS.

Платформенные ветки нужно отдельно обосновать.

---

## 36. Не использовать бинарный runtime patching

Codex должен модифицировать исходный код/patchset Good Bear.

Запрещено решать задачу:

- патчингом установленного `firefox.exe`;
- `LD_PRELOAD`;
- DLL injection;
- изменением памяти процесса;
- внешним MITM proxy.

---

## 37. Документация

К завершению должны существовать:

```text
docs/goodbear-russian-pki-design.md
docs/goodbear-russian-pki-threat-model.md
docs/goodbear-russian-pki-user-behavior.md
goodbear/russian-pki/README.md
```

Threat model должен явно содержать:

- что защищаем;
- от чего защищаем;
- от чего контейнер не защищает;
- почему root не глобальный;
- поведение при смене trust domain;
- ограничения browser extensions;
- ограничения сетевой анонимности.

---

## 38. Definition of Done

Функция готова для Good Bear 1.0 только если выполнены все условия:

- [ ] Russian Trusted Root CA не является глобально доверенным.
- [ ] Точный trust anchor проверяется по cryptographic identity, не по имени.
- [ ] Валидная Russian PKI chain работает в специальном контейнере.
- [ ] Та же chain не получает ordinary browser state.
- [ ] Первый Russian PKI GET автоматически переносится в контейнер.
- [ ] Известные Russian PKI origins сразу маршрутизируются в контейнер.
- [ ] STANDARD → RUSSIAN_PKI вызывает blocking warning.
- [ ] Russian PKI assignment сохраняется после restart.
- [ ] Контейнер sticky.
- [ ] Russian PKI subresources ordinary page блокируются.
- [ ] Cookies изолированы тестами.
- [ ] localStorage изолирован тестами.
- [ ] IndexedDB изолирован тестами.
- [ ] service workers проверены.
- [ ] Password autofill ordinary context не попадает в Russian PKI Container.
- [ ] POST body автоматически не переигрывается.
- [ ] Referrer ordinary context не переносится при auto-migration.
- [ ] `window.opener` не пересекает boundary.
- [ ] Wrong hostname остаётся ошибкой.
- [ ] Expired cert остаётся ошибкой.
- [ ] Fake CA с тем же именем остаётся ошибкой.
- [ ] Bad signature остаётся ошибкой.
- [ ] Intermediate не становится trust anchor.
- [ ] 0-RTT/early-data invariant подтверждён тестом или 0-RTT безопасно отключён.
- [ ] Private Browsing имеет безопасное определённое поведение.
- [ ] UI различает container identity и certificate trust source.
- [ ] Российская криптография не добавлена.
- [ ] Все новые тесты проходят.
- [ ] Затронутые upstream Firefox security tests проходят.
- [ ] Lint/static analysis проходит.
- [ ] Документация и threat model добавлены.

---

## 39. Инструкции Codex по стилю реализации

1. Сначала исследовать текущую ветку Firefox, потом менять код.
2. Не предполагать, что API/файлы старых версий существуют в текущей ветке.
3. Предпочитать минимальные изменения upstream.
4. Новую Good Bear логику держать максимально локально.
5. Не копировать certificate verification logic в browser JS.
6. Не определять trust chain в UI.
7. Не ослаблять NSS/PSM ради удобства.
8. Не писать собственную криптографию.
9. Не добавлять GOST algorithms.
10. Не использовать WebExtension как core implementation.
11. Все security-sensitive изменения покрывать отрицательными тестами.
12. Любой fallback — fail-closed.
13. При конфликте UX и isolation requirement приоритет у isolation.
14. Не повторять автоматически запросы с телом.
15. Не доверять сертификату из сети без проверки manifest/fingerprint.
16. Не менять глобальные настройки certificate verification, если задача решается scoped policy.
17. Если реализация требует крупного изменения NSS, сначала документировать альтернативы и выбрать минимально опасный вариант.

---

## 40. Порядок выполнения работы Codex

### Phase 1 — Reconnaissance

- изучить networking/PSM/NSS path;
- изучить container implementation;
- изучить security UI;
- изучить password/autofill partitioning;
- изучить 0-RTT;
- создать design document.

### Phase 2 — Certificate assets

- получить официальный root/intermediate;
- создать manifest;
- добавить build-time verification.

### Phase 3 — Trust domain

- реализовать secondary verification;
- получить единый `GoodBearTrustDomain`;
- покрыть verifier unit tests.

### Phase 4 — Container

- создать системный Russian PKI Container;
- обеспечить stable identity;
- реализовать persistent assignments.

### Phase 5 — Routing

- top-level GET auto-migration;
- no referrer;
- no opener;
- no POST replay;
- sticky container;
- redirects.

### Phase 6 — Trust history

- STANDARD → RUSSIAN_PKI detection;
- blocking interstitial;
- assignment after confirmation.

### Phase 7 — State protection

- cookies/storage tests;
- password/autofill isolation;
- auth-cache analysis;
- early-data policy.

### Phase 8 — UI

- container marker;
- Russian PKI certificate badge;
- security popup;
- settings;
- list/reset assignments.

### Phase 9 — Tests

- positive tests;
- negative tests;
- integration/browser tests;
- regression tests.

### Phase 10 — Documentation and manual smoke test

- threat model;
- user behavior docs;
- real-site smoke test;
- final implementation report.

---

## 41. Требуемый итоговый отчёт Codex

После завершения работы Codex должен предоставить:

### 41.1. Summary

- что реализовано;
- какие подсистемы Firefox изменены;
- какие security invariants обеспечены.

### 41.2. Changed files

Список файлов с назначением каждого изменения.

### 41.3. Test results

Точные команды и результат:

```text
PASS / FAIL
```

### 41.4. Known limitations

Особенно:

- Private Browsing;
- extensions;
- password manager;
- early data;
- platform-specific limitations.

### 41.5. Security review checklist

Подтвердить отдельно:

```text
Russian Root globally trusted? NO
String-based CA detection? NO
Hostname checks bypassed? NO
Expiry checks bypassed? NO
POST automatically replayed? NO
Ordinary cookies transferred? NO
GOST crypto added? NO
```

---

## 42. Критерий архитектурной корректности

Главный инвариант Good Bear 1.0:

> **Сертификатная цепочка Russian PKI должна быть технически поддержана браузером, но доверие к ней никогда не должно автоматически давать доступ к browser state обычного контекста.**

```text
                         GOOD BEAR 1.0

                    ┌──────────────────┐
                    │  Ordinary tabs   │
                    │                  │
                    │ STANDARD trust   │
                    │ ordinary state   │
                    └────────┬─────────┘
                             │
                   Russian PKI detected
                             │
                    no HTTP state transfer
                             │
                             ▼
                    ┌──────────────────┐
                    │ Russian PKI      │
                    │ Container        │
                    │                  │
                    │ STANDARD trust   │
                    │       +          │
                    │ Russian PKI      │
                    │ scoped trust     │
                    │                  │
                    │ isolated state   │
                    └──────────────────┘
```

Если реализация приводит к тому, что `Russian Trusted Root CA` становится обычным глобальным trust anchor Firefox, задача считается выполненной неправильно, даже если сайты начинают открываться.

---

## 43. Legal, licensing, copyright и branding requirements

`LEGAL.md` и `BRANDING.md` являются нормативной частью Good Bear 1.0 и должны учитываться Codex наравне с данным ТЗ.

### 43.1. Copyright Good Bear

Для оригинальных материалов Good Bear, где юридически применимо, использовать:

```text
Copyright © 2026 Valery Ledovskoy <valery@ledovskoy.com>
```

Этот copyright **не заменяет** существующие copyright/license notices Mozilla или других правообладателей.

Для модифицированных upstream-файлов:

- сохранять исходные notices;
- соблюдать лицензию файла;
- добавлять Good Bear notice только там, где это корректно и необходимо;
- не заявлять владение всем Firefox-derived файлом или кодовой базой.

### 43.2. MPL и source availability

Для MPL-covered файлов:

- сохранять MPL-2.0 compliance;
- Good Bear modifications распространять в соответствии с MPL-2.0;
- при распространении бинарной версии предоставить получателям разумный способ получить соответствующий MPL-covered source с Good Bear modifications;
- не накладывать условия, ограничивающие права на MPL-covered Source Code Form.

Новые Good Bear software source files по умолчанию должны использовать `SPDX-License-Identifier: MPL-2.0`, если для конкретного файла не задокументирована иная совместимая лицензия.

### 43.3. Mozilla/Firefox trademarks

Публичный modified build должен иметь собственную product identity `Good Bear`.

Без отдельного разрешения Mozilla нельзя использовать Mozilla/Firefox trademarks так, чтобы modified build выглядел официальной сборкой Firefox.

Разрешённое описательное attribution должно быть отделено от названия продукта, например:

```text
Good Bear is an independent browser based on Mozilla Firefox open-source code.
```

README/About/Legal должны содержать явный non-affiliation disclaimer.

### 43.4. Russian government non-affiliation

Russian PKI support не должен создавать впечатление, что Good Bear разработан, одобрен или сертифицирован Минцифры, ФСТЭК или иным государственным органом.

Security badge обозначает **источник доверия сертификата**, а не государственную сертификацию браузера.

### 43.5. Certificate redistribution

Производственные Russian PKI certificates должны иметь:

- официальный источник;
- pinned cryptographic hashes;
- документированное происхождение;
- проверенный способ законного распространения.

Если право на перераспространение bytes сертификата в репозитории/дистрибутиве не подтверждено, использовать официальный источник + pinning/import workflow вместо несанкционированной копии.

### 43.6. Brandbook

Codex обязан соблюдать `BRANDING.md`.

Ключевые правила:

- медведь = brand identity;
- Russian PKI badge = security state;
- эти две семантики не смешивать;
- не создавать Good Bear logo путём модификации Firefox logo;
- перед public release выполнить branding audit всех user-visible Firefox/Mozilla identity assets;
- не удалять legal/source attribution при rebranding.

---

## 44. Legal/branding Definition of Done

Публичный Good Bear 1.0 не считается release-ready, пока:

- [ ] Оригинальные Good Bear материалы используют copyright `© 2026 Valery Ledovskoy <valery@ledovskoy.com>` там, где применимо.
- [ ] Upstream copyright/license notices сохранены.
- [ ] MPL-covered corresponding source для бинарного релиза доступен.
- [ ] `LEGAL.md` актуален.
- [ ] `BRANDING.md` актуален.
- [ ] Product display name и основные product identity surfaces используют Good Bear.
- [ ] Официальные Firefox/Mozilla logos не используются как identity публичного modified build.
- [ ] Mozilla/Firefox attribution сформулирован описательно и содержит non-affiliation disclaimer.
- [ ] Russian PKI UI не использует государственную символику без отдельного правового основания.
- [ ] Документация не заявляет endorsement/certification Good Bear со стороны Минцифры/ФСТЭК.
- [ ] Russian PKI certificate assets имеют официальный provenance, pinning и проверенный redistribution method.
- [ ] Good Bear original artwork имеет документированного правообладателя/лицензию.
- [ ] Third-party additions имеют учтённые licenses/notices.
- [ ] Проведён branding audit после последнего upstream rebase.

---

## 45. Отдельное указание по безопасности

Codex не должен считать успешную компиляцию достаточным доказательством корректности.

Для каждого security boundary нужны тесты, которые пытаются этот boundary нарушить.

При сомнении выбирать fail-closed поведение.

---

**Конец ТЗ Good Bear 1.0 / Russian PKI Container.**
