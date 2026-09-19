#!/bin/sh
# SPDX-FileCopyrightText: 2026 dual1208
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
umask 077

source_dir=/etc/peacelove/tls
target_dir=/matrix/traefik/ssl
getent passwd matrix >/dev/null
install -d -o matrix -g matrix -m 0750 "$target_dir"
stage_dir=$(mktemp -d "$target_dir/.tls-sync.XXXXXX")
trap 'rm -rf "$stage_dir"' EXIT HUP INT TERM
install -o matrix -g matrix -m 0640 "$source_dir/privkey.pem" "$stage_dir/privkey.pem"
install -o matrix -g matrix -m 0644 "$source_dir/fullchain.pem" "$stage_dir/fullchain.pem"
openssl x509 -in "$stage_dir/fullchain.pem" -noout -checkend 3600 >/dev/null
openssl x509 -in "$stage_dir/fullchain.pem" -noout -pubkey -out "$stage_dir/cert.pub.pem"
openssl pkey -pubin -in "$stage_dir/cert.pub.pem" -outform DER -out "$stage_dir/cert.pub"
openssl pkey -in "$stage_dir/privkey.pem" -pubout -outform DER -out "$stage_dir/key.pub"
cmp -s "$stage_dir/cert.pub" "$stage_dir/key.pub"
if cmp -s "$stage_dir/fullchain.pem" "$target_dir/fullchain.pem" &&
   cmp -s "$stage_dir/privkey.pem" "$target_dir/privkey.pem"; then
    exit 0
fi
mv "$stage_dir/privkey.pem" "$target_dir/privkey.pem"
mv "$stage_dir/fullchain.pem" "$target_dir/fullchain.pem"
# Reloading file contents alone is not a reliable Traefik certificate refresh.
# A renewal briefly restarts only Matrix's reverse proxy; peacelove hot-reloads.
systemctl try-restart matrix-traefik.service
