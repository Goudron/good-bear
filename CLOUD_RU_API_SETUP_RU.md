# Cloud.ru API: подготовка Windows-сборщика Good Bear

Этот файл описывает одноразовую подготовку доступа к Cloud.ru. Он не содержит
секретов. Секреты не следует добавлять в Git, логи, backlog или отправлять в чат.

## Цель

Создать через API управляемую виртуальную машину Windows Server для сборки
Good Bear. Принятая для M15-03 конфигурация использует доступный Marketplace
образ Windows Server 2022 (`wind-2022-dc-evo-prod`); он является только хостом
сборки и не ограничивает целевой дистрибутив Windows x64. Требуемая
конфигурация совпадает с Ubuntu-сборщиком:

- 4 vCPU;
- 16 ГиБ RAM;
- SSD 250 ГБ;
- публичный IP, исходящий интернет и доступ для удалённого администрирования.

Виртуальная машина будет получать уникальные теги Good Bear. Автоматизация
сможет создавать, проверять, запускать, останавливать и удалять только такие
явно идентифицированные ресурсы.

## 1. Выберите проект и проверьте квоты

Откройте [консоль Cloud.ru](https://console.cloud.ru/) и выберите нужный проект.
Идентификатор проекта Good Bear уже известен:

```text
ed75ec2f-6b92-4687-aabf-e0e41655b03b
```

Проверьте, что для него доступны квоты для
одной VM с 4 vCPU, 16 ГиБ RAM, SSD 250 ГБ и Marketplace-образом Windows Server.
При необходимости увеличьте квоту до начала автоматизации.

## 2. Создайте сервисный аккаунт

В разделе управления доступом создайте отдельный сервисный аккаунт Good Bear.
Ему нужны права на:

- виртуальные машины: inspect/create/start/stop/delete;
- сети, подсети, security groups и публичные IP;
- чтение аудита и операций;
- управление Marketplace-образом Windows Server, выбранным для M15-03.

Если в интерфейсе нельзя уверенно выбрать минимальные роли, для первого
развёртывания допустима роль администратора проекта (`eiv.admin`/Project Admin).
После успешной настройки права следует сузить.

## 3. Создайте ключ доступа API

Для сервисного аккаунта создайте ключ доступа. Cloud.ru выдаёт два значения:

- `keyId` — идентификатор ключа;
- `secret` — секрет ключа.

`secret` обычно показывается однократно. Не отправляйте его в чат и не храните
в проекте.

## 4. Сохраните реквизиты локально

В терминале выполните:

```bash
install -d -m 700 /home/valery/.config/goodbear
nano /home/valery/.config/goodbear/cloudru-access.json
chmod 600 /home/valery/.config/goodbear/cloudru-access.json
```

Содержимое файла:

```json
{
  "key_id": "<Cloud.ru Key ID>",
  "secret": "<Cloud.ru Key Secret>",
  "project_id": "ed75ec2f-6b92-4687-aabf-e0e41655b03b"
}
```

После сохранения сообщите только путь к файлу:

```text
/home/valery/.config/goodbear/cloudru-access.json
```

Не сообщайте значения из файла. Автоматизация прочитает их локально, получит
временный bearer token и не будет записывать токен или секрет в артефакты.

## 5. Подготовьте сеть

Нужны либо существующие IDs зоны, подсети и security group, либо права на их
создание API. В security group должны быть разрешены:

- исходящий HTTPS/DNS/системный трафик;
- входящий трафик по умолчанию не требуется: текущий runner Good Bear работает
  только через исходящий HTTPS;
- VNC/serial-console допускается только как аудируемое provider recovery, а не
  как постоянный доступ;
- SSH/WinRM/RDP не следует открывать ради передачи исходников или сборки.

## 6. Образ Windows

M15-03 использует доступный Marketplace-образ Windows Server 2022. Локальная
VM, RAW VirtIO-образ, Sysprep и графическая ручная настройка не являются
приёмочными входами. Средства сборки закрепляются и проверяются на облачном
host через outbound-only self-hosted runner.

## 7. Шифрованный GitHub release-asset для исходного bundle

Firefox + Good Bear source bundle нельзя помещать в GitHub в открытом виде.
Для M15-03 используется один зашифрованный release-asset: локальный bundle
шифруется AES-256-CBC с PBKDF2-SHA-512 (600 000 итераций) и случайной
passphrase. Это шифрование, а не обфускация.

- в GitHub размещается только ciphertext;
- passphrase хранится только в локальном файле с правами `0600` и в GitHub
  Actions secret `GOODBEAR_M15_03_SOURCE_PASSPHRASE`;
- runner расшифровывает bundle только в своём рабочем каталоге и немедленно
  сверяет SHA-256 исходного manifest и source bundle по M15-01;
- release, workflow и логи не публикуют plaintext, ключ или URL с ключом.

Ключ создаётся локально командой:

```bash
python3 tools/m15_03_github_encrypted_transport.py init-key \
  --key-file /home/valery/.config/goodbear/m15-03-github-source-passphrase
```

Автоматизация создаёт ключ, добавляет его в секрет GitHub, шифрует только
проверенный bundle и публикует ciphertext как release-asset. Object Storage,
отдельный bucket и его ключи для этой схемы не нужны.

## 8. Что сделает автоматизация после подготовки

1. Получит временный токен на `https://iam.api.cloud.ru/api/v1/auth/token`.
2. Через `https://compute.api.cloud.ru` проверит проект, квоты, зоны, сеть,
   образы и уникальность Good Bear ресурсов.
3. Создаст или переиспользует только tagged Windows VM с параметрами выше.
4. Запишет credential-free inventory, конфигурацию и статус lifecycle.
5. Передаст проверенный source bundle через зашифрованный GitHub release-asset,
   настроит headless remote build и вернёт только объявленные логи/артефакты по
   transport contract.
6. Остановит VM после завершения задачи; удалит её только когда образ, логи и
   результаты успешно проверены и удаление соответствует текущей задаче.

## Официальная документация

- [Аутентификация API виртуальных машин](https://cloud.ru/docs/virtual-machines/ug/topics/api-ref__authentication)
- [Справочник API виртуальных машин](https://cloud.ru/docs/virtual-machines/ug/topics/api-ref)
- [Создание VM через API](https://cloud.ru/docs/virtual-machines/ug/topics/guides__create-vm)
