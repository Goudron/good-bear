#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

set -eu
export DEBIAN_FRONTEND=noninteractive

# Keep package selection independent of a cloud image's configured mirrors.
# The snapshot URI and every direct package below are exact lock inputs.
apt_state=$(mktemp -d)
cleanup() {
  rm -rf "$apt_state"
}
trap cleanup EXIT
mkdir "$apt_state/lists"
# The minimal official OCI image has the Ubuntu archive signing key, but no
# HTTPS CA bundle. Bootstrap the exactly pinned public CA package through the
# signed official HTTP archive; never disable TLS or apt signature validation.
if [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
  cat >"$apt_state/bootstrap.list" <<'EOF'
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu/ noble main
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu/ noble-updates main
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://security.ubuntu.com/ubuntu/ noble-security main
EOF
  echo 'Preparing pinned HTTPS certificates from the signed Ubuntu archive'
  apt-get -o Dir::Etc::sourcelist="$apt_state/bootstrap.list" -o Dir::Etc::sourceparts=- -o Dir::State::lists="$apt_state/lists" update -o APT::Update::Error-Mode=any -o Acquire::Retries=3
  apt-get -o Dir::Etc::sourcelist="$apt_state/bootstrap.list" -o Dir::Etc::sourceparts=- -o Dir::State::lists="$apt_state/lists" install -y --no-install-recommends ca-certificates=20260601~24.04.1
  rm -rf "$apt_state/lists"
  mkdir "$apt_state/lists"
fi
cat >"$apt_state/sources.list" <<'EOF'
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20260913T000000Z noble main restricted universe multiverse
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20260913T000000Z noble-updates main restricted universe multiverse
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20260913T000000Z noble-backports main restricted universe multiverse
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20260913T000000Z noble-security main restricted universe multiverse
EOF
apt-get -o Dir::Etc::sourcelist="$apt_state/sources.list" -o Dir::Etc::sourceparts=- -o Dir::State::lists="$apt_state/lists" update -o APT::Update::Error-Mode=any -o Acquire::Retries=3
apt-get -o Dir::Etc::sourcelist="$apt_state/sources.list" -o Dir::Etc::sourceparts=- -o Dir::State::lists="$apt_state/lists" install -y --no-install-recommends \
  ca-certificates=20260601~24.04.1 tzdata=2026c-0ubuntu0.24.04.1 locales=2.39-0ubuntu8.9 \
  python3.12=3.12.3-1ubuntu0.17 python3.12-venv=3.12.3-1ubuntu0.17 python3-pip=24.0+dfsg-1ubuntu1.3 \
  make=4.3-4.1build2 git=1:2.43.0-1ubuntu7.3 gnupg=2.4.4-2ubuntu17.6 dpkg-dev=1.22.6ubuntu6.6 fakeroot=1.33-1 \
  build-essential=12.10ubuntu1 g++=4:13.2.0-7ubuntu1 g++-13=13.3.0-6ubuntu2~24.04.1 libstdc++-13-dev=13.3.0-6ubuntu2~24.04.1 autoconf2.13=2.13-69 nasm=2.16.01-1build1 yasm=1.3.0-4 zip=3.0-13ubuntu0.2 unzip=6.0-28ubuntu4.1 pkg-config=1.8.1-2build1 \
  curl=8.5.0-2ubuntu10.13 file=1:5.45-3build1 bzip2=1.0.8-5.1ubuntu0.1 xz-utils=5.6.1+really5.4.5-1ubuntu0.3 \
  libgtk-3-dev=3.24.41-4ubuntu1.3 libdbus-glib-1-dev=0.112-3build2 libasound2-dev=1.2.11-1ubuntu0.3 libpulse-dev=1:16.1+dfsg1-2ubuntu10.1 \
  libx11-xcb-dev=2:1.8.7-1build1 libxcomposite-dev=1:0.4.5-1build3 libxdamage-dev=1:1.1.6-1build1 libxrandr-dev=2:1.5.2-2build1 libxss-dev=1:1.2.3-1build3 libxt-dev=1:1.2.1-1.2build1 \
  libdrm-dev=2.4.125-1ubuntu0.1~24.04.2 libgbm-dev=25.2.8-0ubuntu0.24.04.2 libegl1-mesa-dev=25.2.8-0ubuntu0.24.04.2 libgl1-mesa-dev=25.2.8-0ubuntu0.24.04.2 libvulkan-dev=1.3.275.0-1build1 \
  libpci-dev=1:3.10.0-2build1 libssl-dev=3.0.13-0ubuntu3.15 libxml2=2.9.14+dfsg-1.3ubuntu3.8 libfontconfig1-dev=2.15.0-1.1ubuntu2 libjpeg-dev=8c-2ubuntu11 libpng-dev=1.6.43-5ubuntu0.6 \
  zlib1g-dev=1:1.3.dfsg-3.1ubuntu2.2 libbz2-dev=1.0.8-5.1ubuntu0.1 liblzma-dev=5.6.1+really5.4.5-1ubuntu0.3 libunwind-dev=1.6.2-3build1.1
sed -i 's/^# *\(ru_RU.UTF-8 UTF-8\)/\1/' /etc/locale.gen
locale-gen ru_RU.UTF-8
ln -snf /usr/share/zoneinfo/Europe/Moscow /etc/localtime
echo Europe/Moscow >/etc/timezone
# The cloud image may already contain the ordinary build account after a
# resumed bootstrap.  Do not modify an existing account implicitly; only
# create it when absent, and fail closed if an unrelated account reuses the
# reserved name with incompatible attributes.
if ! builder_entry=$(getent passwd builder); then
  useradd --create-home --shell /bin/bash builder
else
  builder_uid=$(printf '%s\n' "$builder_entry" | cut -d: -f3)
  builder_home=$(printf '%s\n' "$builder_entry" | cut -d: -f6)
  builder_shell=$(printf '%s\n' "$builder_entry" | cut -d: -f7)
  [ "$builder_uid" -ge 1000 ] || {
    echo "existing builder account is not an ordinary user" >&2
    exit 1
  }
  [ "$builder_home" = "/home/builder" ] || {
    echo "existing builder account has an unexpected home directory" >&2
    exit 1
  }
  [ "$builder_shell" = "/bin/bash" ] || {
    echo "existing builder account has an unexpected login shell" >&2
    exit 1
  }
fi
