#!/bin/sh
# SPDX-FileCopyrightText: 2026 dual1208
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
umask 077

refresh_requested=false
if [ "$#" -gt 1 ]; then
    echo "usage: matrix-tls-sync [--refresh]" >&2
    exit 2
fi
if [ "$#" -eq 1 ]; then
    if [ "$1" != "--refresh" ]; then
        echo "usage: matrix-tls-sync [--refresh]" >&2
        exit 2
    fi
    refresh_requested=true
fi

source_dir=/etc/peacelove/tls
target_dir=/matrix/traefik/ssl
provider_file=/matrix/traefik/config/provider.yml
getent passwd matrix >/dev/null
install -d -o matrix -g matrix -m 0750 "$target_dir"
stage_dir=$(mktemp -d "$target_dir/.tls-sync.XXXXXX")
provider_stage=
cleanup() {
    rm -rf "$stage_dir"
    if [ -n "$provider_stage" ]; then
        rm -f "$provider_stage"
    fi
}
trap cleanup EXIT HUP INT TERM
install -o matrix -g matrix -m 0640 "$source_dir/privkey.pem" "$stage_dir/privkey.pem"
install -o matrix -g matrix -m 0644 "$source_dir/fullchain.pem" "$stage_dir/fullchain.pem"
openssl x509 -in "$stage_dir/fullchain.pem" -noout -checkend 3600 >/dev/null
openssl x509 -in "$stage_dir/fullchain.pem" -noout -pubkey -out "$stage_dir/cert.pub.pem"
openssl pkey -pubin -in "$stage_dir/cert.pub.pem" -outform DER -out "$stage_dir/cert.pub"
openssl pkey -in "$stage_dir/privkey.pem" -pubout -outform DER -out "$stage_dir/key.pub"
cmp -s "$stage_dir/cert.pub" "$stage_dir/key.pub"
files_changed=true
if cmp -s "$stage_dir/fullchain.pem" "$target_dir/fullchain.pem" &&
   cmp -s "$stage_dir/privkey.pem" "$target_dir/privkey.pem"; then
    files_changed=false
else
    mv "$stage_dir/privkey.pem" "$target_dir/privkey.pem"
    mv "$stage_dir/fullchain.pem" "$target_dir/fullchain.pem"
fi

if [ "$files_changed" = false ] && [ "$refresh_requested" = false ]; then
    exit 0
fi

# Replacing the watched dynamic configuration file makes Traefik reload the
# certificate without stopping its container or listening sockets. Never start
# Traefik here when an administrator has stopped it.
if systemctl is-active --quiet matrix-traefik.service; then
    if [ ! -f "$provider_file" ]; then
        echo "Traefik provider file is missing: $provider_file" >&2
        exit 1
    fi
    provider_stage=$(mktemp "$(dirname "$provider_file")/.provider.yml.XXXXXX")
    cp -p "$provider_file" "$provider_stage"
    mv -f "$provider_stage" "$provider_file"
    provider_stage=
fi
