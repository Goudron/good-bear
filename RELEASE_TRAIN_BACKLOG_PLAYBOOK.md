# Good Bear: плейбук сведения будущего release train в один backlog

Этот control-плейбук — единственная точка генерации нового versioned Good Bear backlog. Он
объединяет новую базу Firefox и новые функции в один dependency-ordered plan. Он не запускает ни
одну задачу из созданного backlog.

## Required composition inputs

До создания файла должны быть готовы:

1. заполненный intake нового Good Bear/Firefox version pair;
2. Firefox migration block из `FIREFOX_VERSION_UPGRADE_BACKLOG_PLAYBOOK.md`;
3. один или несколько approved feature-task blocks из
   `GOOD_BEAR_FEATURE_BACKLOG_PLAYBOOK.md`;
4. release mode, supported platforms, locale, known non-goals и current public-release boundary;
5. explicit statement, whether the version is a source-only planning release, local candidate or
   public release. Public delivery is never inferred.

Не объединяйте feature brief с отсутствующим upstream pin. Если feature не зависит от новой базы,
он всё равно получает compatibility/rebase gate в этом едином release train.

## Создание файла

1. Нормализовать product version в filename и epic ID: `1.1` → `good_bear_1_1` и `GB110`.
2. Создать ровно один файл:

   ```text
   backlogs/good_bear_<version>_firefox_<base>_<short_topic>_backlog_<yyyy-mm-dd>.md
   ```

3. Начать с current-state assessment, intake assumptions, scope, non-goals, public-release
   boundary и inherited Good Bear invariants. Указать, что созданный backlog не является
   authorization to execute tasks.
4. Расположить milestones в следующем порядке, убирая пустые группы, но не сокращая gates:

   | Milestone | Содержимое |
   | --- | --- |
   | 1 | Immutable Firefox baseline, product/version identity, dependency/toolchain disposition. |
   | 2 | Ordered patch rebase и upstream owner dispositions. |
   | 3 | Новые функции Good Bear; каждая feature block сохраняет свои dependencies. |
   | 4 | Cross-feature security, privacy, RU UI/l10n, hosted-service и migration gates. |
   | 5 | Native Windows/Ubuntu packaging, clean-machine, reproducibility, SBOM/provenance/source-offer gates. |
   | 6 | Release freeze and publication only if maintainer explicitly asks for it. |

5. Каждая строка таблицы получает exactly one approved model, one minimum reasoning level и
   executable acceptance. Security/release rows остаются High или Extra High. Не дублировать
   один и тот же upstream pin, package build или final gate для каждой функции.
6. В конце добавить execution protocol: one approved task at a time, targeted reads, real progress
   for long-running commands, fail-closed blockers, no remote/push/tag/release without distinct
   maintainer approval.

## Правила зависимостей

* Ни одна feature implementation task не обходит immutable Firefox pin и relevant patch
  disposition.
* Feature UI cannot be promoted before its Russian copy, accessibility states and security-state
  visual review are covered.
* Feature touching profile/network/trust/container must pass its negative tests before packaging.
* Source/configuration change invalidates candidate evidence affected by it; package-only or
  installer-only recovery is valid only under its declared immutable boundary.
* One frozen source revision and one version pair feed both native candidates; platform discrepancy,
  ambiguous provenance or missing source offer blocks the release.

## Definition of ready

The generated backlog is ready for maintainer review only when it has one target version, one
Firefox pin task, explicit feature blocks, no hidden public-release assumption, all inherited
security boundaries, Windows/Ubuntu and `ru` scope, final quality/reproducibility/source-offer
gates, and a task-by-task approval protocol. It becomes executable only when the maintainer
approves a concrete task from it.
