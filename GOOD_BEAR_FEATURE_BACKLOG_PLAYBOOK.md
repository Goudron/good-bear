# Good Bear: плейбук генерации бэклога новой функциональности

Этот control-плейбук превращает намерение maintainer добавить функцию Good Bear в задачи для
единого будущего release train. Он не реализует функцию и не разрешает её реализацию.

## Карточка feature brief

Maintainer предоставляет карточку в следующем виде:

```text
Название:
Пользовательская задача и для кого это нужно:
Наблюдаемое поведение и границы применения:
Что должно оставаться неизменным:
Русский UI / доступность:
Данные, профиль, сеть и внешние сервисы:
Затрагиваемые платформы и поставки:
Негативные сценарии / недопустимое поведение:
Совместимость и миграция:
Явные non-goals:
```

Если не определены пользовательская задача, граница применения или недопустимое поведение,
feature brief неполон. Генератор должен запросить эти данные, а не угадывать продуктовую политику.

## Разбор границы

1. Классифицировать функцию: local UI, packaging, browser integration, network/service, profile
   data, certificate/trust, container/isolation, security UI, update/release или смешанная.
2. До проектирования прочитать только целевые owners, соседние tests и relevant invariant. Не
   сканировать дерево Firefox целиком и не копировать upstream behaviour по памяти.
3. Если затронуты trust, certificate, container, navigation, credentials, profile data, request
   body, network endpoint, updater или release provenance, минимум reasoning — High, а для
   adversarial/release-critical решения — Extra High. Для таких задач обязательны отдельные
   positive и fail-closed negative acceptance.
4. Выделить явные inputs/outputs: preference, manifest, typed API, OriginAttributes, Fluent
   message, package entry, network request, local data, migration или release metadata. Не
   заменять это design document: граница должна стать кодом, machine-readable contract или test.

## Шаблон задач для одной функции

Вставляйте только необходимые строки; каждая строка остаётся independently approvable:

| Очередность | Обязательная задача, если применима | Acceptance |
| --- | --- | --- |
| 1 | Targeted reconnaissance и owner/invariant map | Названы конкретные owners, adjacent tests, upstream delta и запрещённые обходы. |
| 2 | Typed policy/configuration contract | Невозможны implicit enablement, string-based trust inference и undefined fallback. |
| 3 | Bounded implementation | Меняется один согласованный subsystem owner; RU UI и accessibility включены при наличии UI. |
| 4 | Positive и negative tests | Проверяются нормальный сценарий, отказ, restart/migration при необходимости и отсутствие пересечения границ. |
| 5 | Upstream/regression integration | Запускаются только затронутые Firefox и Good Bear suites; snapshot не обновляется без manual review. |
| 6 | Packaging/release mapping | Поставка, source offer, SBOM/provenance, notices и clean-install impact проверены, если функция их меняет. |

## Особые правила функций Good Bear

Функция не может:

* глобализировать российское доверие, заменить стандартную X.509 validation или ослабить исходную
  ошибку TLS;
* переносить ordinary browser state или request body через container boundary;
* добавлять неописанный hosted endpoint, telemetry identifier, background request или fallback;
* заявлять Mozilla/government affiliation, certification, signing, MAR или auto-update без
  отдельной проверенной authority и release task;
* добавлять shipped locale помимо `ru` либо платформу помимо утверждённой границы без отдельного
  decision и clean-machine evidence.

## Обязательный результат

Выход — упорядоченный feature-task block с ID, essence, model/reasoning, dependencies и
acceptance. Его передают в `RELEASE_TRAIN_BACKLOG_PLAYBOOK.md` вместе с Firefox migration block.
Если функция меняет общий invariant, intake остаётся блокером до явного решения maintainer; такой
инвариант нельзя silently redefine внутри feature task.
