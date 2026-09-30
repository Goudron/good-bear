# Good Bear: плейбук генерации бэклога обновления Firefox

Этот control-плейбук создаёт раздел миграции на новую базу Firefox для следующего выпуска Good
Bear. Он применяется до каких-либо изменений исходников, запуска builder-VM, сборки, тега или
публикации. Сам плейбук не является бэклогом и не даёт разрешения на выполнение его задач.

## Входные данные

До генерации бэклога maintainer фиксирует один intake:

| Поле | Обязательно | Правило |
| --- | --- | --- |
| Версия Good Bear | да | Новая продуктовая версия; не выводится из версии Firefox. |
| Предыдущий публичный Good Bear tag | да | Точная отправная точка и известные release boundaries. |
| Целевая Firefox версия | да | Один stable desktop release, например Firefox 157.x. |
| Дата и тема release train | да | Используются в имени нового backlog-файла. |
| Поддерживаемые поставки | да | Ubuntu LTS amd64 `.deb`, Windows x64 installer и единственная locale `ru`, если maintainer явно не изменил границу. |
| Режим выпуска | да | Например public unsigned; не предполагает ключ, MAR или auto-update. |
| Одобренные изменения Good Bear | нет | Ссылки на feature briefs, обработанные по `GOOD_BEAR_FEATURE_BACKLOG_PLAYBOOK.md`. |

Отсутствие любой обязательной строки означает, что генерируется только список вопросов, а не
исполняемый backlog.

## Процедура генерации

1. Создать первый milestone только для immutable upstream baseline. Задача должна получить с
   авторитетных Mozilla sources точную release version, revision, archive URL, SHA-256/SHA-512,
   detached signature/key disposition, дату получения и security-support disposition. «Latest» и
   floating URL запрещены.
2. Сформировать узкий impact map от предыдущей базы к новой. Разрешены только владельцы Good Bear
   patches, PSM/NSS, container/OriginAttributes routing, browser security UI, Fluent/l10n, branding,
   installer, packaging, updater и hosted-service boundary. Рекурсивный обзор дерева Firefox не
   является методом планирования.
3. Для каждого patch из `patches/series` создать явный disposition: applies unchanged, needs
   rebase, superseded upstream, split, removed with rationale, or blocker. Любой неясный hunk или
   security regression — отдельный blocker, а не silently dropped patch.
4. Создать отдельные bounded tasks для rebase, typed/executable contracts, Russian UI/l10n audit,
   affected upstream tests и Good Bear positive/negative tests. Не объединять архитектурное решение
   и массовое редактирование в одну задачу.
5. Вставить native-build readiness tasks для обеих платформ. Windows preflight обязан проверить
   полный выбранный NSIS `BRANDING_FILES`, pinned `7zz.exe`, `mozmake -n -C
   browser/installer/windows instgen/helper.exe`, `default.locale == ru` и кандидат
   `*.ru.win64.*`. Ubuntu preflight обязан проверить фактические package prerequisites до LTO.
6. Зафиксировать recovery boundary: installer/package-only repair использует только точный
   downstream target и не запускает `mach configure` или top-level build; любое изменение source,
   configuration, toolchain, branding или locale требует нового full-LTO build.
7. Завершить блок migration gates: clean source materialization, patch application, targeted
   compile/test, profile compatibility where affected, RU screenshots/accessibility where affected,
   SBOM/provenance inputs, hash evidence и one-time native candidate builds. Каждая длительная
   команда должна печатать реальный прогресс.

## Неподлежащие ослаблению инварианты

Сгенерированный backlog обязан повторить следующие условия как executable acceptance:

* российский trust anchor никогда не становится глобально доверенным;
* идентификация trust anchor криптографическая, без CN/O/OU/subject heuristics;
* обычная X.509/TLS validation и её исходная ошибка имеют приоритет;
* cookies, credentials, referrer, opener, request body, storage, connection reuse, early data и
  subresources не пересекают container boundary; fallback fail-closed;
* `ru` — единственная shipped locale; Mozilla/government affiliation, certification и неподтверждённая
  signing/update functionality не заявляются;
* full Firefox source, private keys, profiles, caches и local candidates не попадают в public
  source offer.

## Обязательный результат

Результат этого плейбука — блок задач `Firefox migration` для единого release-train backlog,
созданного только через `RELEASE_TRAIN_BACKLOG_PLAYBOOK.md`. Он должен содержать pins, owner
dispositions, зависимость от feature tasks, негативные security tests, Windows/Ubuntu readiness и
fail-closed blockers. Он не создаёт сам по себе второй backlog, tag, binary или GitHub release.
