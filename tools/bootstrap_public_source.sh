#!/usr/bin/env bash
# Reconstruct the pinned Good Bear source tree without storing Firefox sources
# or certificate bytes in this repository.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"

for command in curl python3 sha256sum git openssl; do
  command -v "$command" >/dev/null || {
    echo "ERROR: required command is unavailable: $command" >&2
    exit 1
  }
done

readarray -t baseline < <(python3 - <<'PY'
import json
config = json.load(open('config/firefox-baseline.json', encoding='utf-8'))
source = config['source']
print(source['archive_path'])
print(source['archive_url'])
print(source['sha256'])
PY
)
archive=${baseline[0]}
url=${baseline[1]}
expected_sha256=${baseline[2]}
mkdir -p "$(dirname "$archive")"

if [[ ! -f "$archive" ]]; then
  echo "==> Downloading pinned Firefox source archive"
  curl --fail --location --proto '=https' --tlsv1.2 --output "$archive.part" "$url"
  mv "$archive.part" "$archive"
fi
printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum --check --status || {
  echo "ERROR: Firefox archive SHA-256 mismatch" >&2
  exit 1
}

echo "==> Materializing patched Good Bear source"
python3 tools/materialize_firefox_source.py --archive "$archive"

echo "==> Materializing pinned Russian locale input and Good Bear translations"
python3 tools/materialize_pinned_russian_l10n.py

echo "==> Importing pinned Russian PKI inputs from official sources"
python3 tools/import_m3_03_certificates.py \
  --cache-dir artifacts/certificates/cache \
  --output-dir artifacts/certificates/build-inputs/current

if [[ ${1:-} == "--build" ]]; then
  echo "==> Installing pinned toolchain"
  python3 tools/install_toolchain.py
  echo "==> Building Russian-only Good Bear candidate"
  python3 tools/build_host_russian.py \
    --objdir artifacts/development/public-host-obj --jobs 4
fi

echo "Good Bear source preparation completed"
