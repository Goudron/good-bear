# Исходные материалы Good Bear 1.0

Это corresponding source для Good Bear 1.0. Исходный код Good Bear, включая
изменения файлов, покрытых MPL, предоставляется на условиях **Mozilla Public License 2.0**.
Условия этого offer не ограничивают права на Source Code Form по
MPL 2.0. Оригинальные графические материалы имеют отдельную отмеченную в
inventory лицензию; Mozilla и сторонние notices сохраняются в исходном архиве
Firefox и в `config/m10-07-source-release-inventory.json`.

Репозиторий намеренно содержит только упорядоченный набор патчей Good Bear,
overlay, русскую локализацию, исходные материалы сборки, inventory, checksums
и provenance. **Полный исходный код Firefox здесь не хранится.** Его точный
архив Firefox 156.0, ревизия и SHA-256 закреплены в
`config/firefox-baseline.json` и `config/m10-07-source-release-inventory.json`.
Состав публичного дерева проверяется так:

```bash
python3 tools/verify_public_source_offer.py
```

Проверка анализирует Git index, а не рабочий каталог. Поэтому скачанный Firefox,
objdir, cache, профиль и локальный кандидат могут существовать только локально
и не могут быть случайно добавлены в публичный offer. Она также отвергает
архивы и бинарные дистрибутивы, credentials, private keys и любой неописанный
путь. Полный список разрешённых категорий и границы recovery зафиксированы в
`corresponding_source.source_offer` inventory.

## Получение исходного дерева

Для подготовки дерева нужны `curl`, `python3`, `git`, `openssl` и `sha256sum`.
На чистой копии выполните:

```bash
git clone https://github.com/Goudron/good-bear.git
cd good-bear
./tools/bootstrap_public_source.sh
```

Скрипт скачивает только закреплённый upstream-архив по HTTPS, проверяет его
SHA-256, применяет каждый патч из `patches/series` по порядку, materialize
точный commit русской l10n и проверяет Good Bear Fluent overlay. Сертификаты
берутся только с закреплённых официальных адресов и проверяются до добавления в
локальные входы сборки; bytes сертификатов не коммитятся и не загружаются во
время работы браузера.

`config/m10-07-source-release-inventory.json` — машиночитаемый inventory
происхождения, notices и прав; `release/good-bear-1.0/` содержит публичные
SHA-256, SBOM, provenance и индекс notices для двух unsigned дистрибутивов.
Полный набор notices в установленном Firefox остаётся авторитетным; индекс не
заменяет его.

## Ubuntu 24.04 LTS amd64

Ubuntu — единственная Linux-цель Good Bear 1.0. Сначала проверяются lock и
фактические package prerequisites, затем печатается и валидируется canonical
host context:

```bash
python3 tools/verify_ubuntu_environment.py
sudo bash build/ubuntu/install-packages.sh
python3 tools/host_build_context.py --objdir artifacts/development/public-host-obj --intent russian-repack
```

Для native full-LTO сборки нужен отдельно предоставленный Safe Browsing input,
который не является частью source offer и не должен попадать в Git, logs или
release assets. После его проверки передайте внешний путь явно:

```bash
python3 tools/build_host_russian.py \
  --objdir artifacts/development/public-host-obj \
  --jobs 4 --release-lto \
  --safebrowsing-key-file /абсолютный/внешний/путь/к/input
```

Если исходники, `mozconfig`, `config.status`, связанный base package и его
receipt не менялись, ошибка создания `.deb` исправляется только package-only
путём `tools/build_m13_06_ubuntu_deb.py`. Он принимает уже собранный archive и
source manifest, не вызывает `mach configure` и не вызывает `mach build`.
При изменении исходников или конфигурации этот recovery запрещён: нужен новый
полный native build, а не повторное использование objdir.

## Windows Server 2022 x64

Windows собирается нативно на закреплённой Windows Server 2022 x64-среде с
lock `config/m15-03-windows-toolchain-lock.json`. До LTO обязательно проходят
проверка Good Bear NSIS branding и dry-run реального Windows installer owner:

```powershell
py -3 tools/verify_nsis_branding_assets.py
mozmake -n -C browser/installer/windows instgen/helper.exe
py -3 tools/preflight_m15_cloud_windows.py --manifest <manifest> --bundle <bundle> --expected-manifest-sha256 <sha256> --expected-bundle-sha256 <sha256> --report <внешний-путь-к-report.json>
```

`mozmake` должен перечислить и разрешить полный `BRANDING_FILES` выбранного
Good Bear branding tree до любого LTO. Только после успешных preflight выполняются
`./mach build -j4` и `./mach build installers-ru` в materialized Windows source.

Если изменён только installer после успешной неизменённой source/configuration
сборки, допустим единственный recovery:

```powershell
./mach build installers-ru
```

В installer-only recovery **не запускать `mach configure`** и не запускать
top-level `./mach build`: это пересобирает базовый Firefox и нарушает границу
recovery. Любое изменение source, toolchain, configuration или branding требует
новой полной native LTO-сборки.

## Публичная граница

В репозиторий не включаются Firefox source tree/архив, object directories,
`dist`, build caches, profiles, credentials, private keys, локальные кандидаты,
непроверенные artifacts и исходные preview-кандидаты artwork. Дистрибутивы Good
Bear 1.0 публикуются отдельно как unsigned GitHub Release assets вместе с
checksums, SBOM, provenance, notices и этим source offer. В нём нет claim о
подписи, MAR или auto-update.
