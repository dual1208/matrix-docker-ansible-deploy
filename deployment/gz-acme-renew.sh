#!/bin/bash
# SPDX-FileCopyrightText: 2026 dual1208
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
umask 077

readonly domain=8.163.2.191
readonly acme_home=/root/.acme.sh
readonly certificate=/etc/peacelove/tls/fullchain.pem
readonly status_dir=/var/lib/gz-acme-renew
readonly status_file=$status_dir/status
readonly lock_file=/run/lock/gz-acme-renew.lock
readonly max_attempts=3

mkdir -p "$status_dir"
chmod 0755 "$status_dir"
exec 9>"$lock_file"
if ! /usr/bin/flock -n 9; then
    echo "gz-acme-renew result=skipped reason=lock-held"
    exit 0
fi

certificate_expiry_epoch() {
    local not_after
    not_after=$(/usr/bin/openssl x509 -in "$certificate" -noout -enddate 2>/dev/null) || return 1
    /usr/bin/date -u -d "${not_after#notAfter=}" +%s
}

validate_certificate() {
    /usr/bin/openssl x509 -in "$certificate" -noout -checkend 86400 >/dev/null &&
        /usr/bin/openssl x509 -in "$certificate" -noout -checkip "$domain" >/dev/null &&
        /usr/bin/openssl verify -CApath /etc/ssl/certs -untrusted "$certificate" "$certificate" >/dev/null
}

write_status() {
    local result=$1
    local detail=$2
    local checked_at expiry_epoch expiry_at remaining tmp
    checked_at=$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)
    expiry_epoch=$(certificate_expiry_epoch 2>/dev/null || printf '0')
    if [ "$expiry_epoch" -gt 0 ]; then
        expiry_at=$(/usr/bin/date -u -d "@$expiry_epoch" +%Y-%m-%dT%H:%M:%SZ)
        remaining=$((expiry_epoch - $(/usr/bin/date -u +%s)))
    else
        expiry_at=unknown
        remaining=0
    fi
    tmp=$(/usr/bin/mktemp "$status_dir/.status.XXXXXX")
    {
        printf 'checked_at_utc=%s\n' "$checked_at"
        printf 'result=%s\n' "$result"
        printf 'detail=%s\n' "$detail"
        printf 'certificate_not_after_utc=%s\n' "$expiry_at"
        printf 'certificate_seconds_remaining=%s\n' "$remaining"
    } >"$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$status_file"
}

attempt=1
last_detail=not-run
while [ "$attempt" -le "$max_attempts" ]; do
    echo "gz-acme-renew attempt=$attempt/$max_attempts"
    if /usr/bin/timeout 300 "$acme_home/acme.sh" --cron --home "$acme_home"; then
        if validate_certificate; then
            write_status ok certificate-valid
            echo "gz-acme-renew result=ok certificate=$(certificate_expiry_epoch)"
            exit 0
        fi
        last_detail=certificate-validation-failed
    else
        last_detail="acme-exit-$?"
    fi
    if [ "$attempt" -lt "$max_attempts" ]; then
        /usr/bin/sleep $((attempt * 30))
    fi
    attempt=$((attempt + 1))
done

write_status failed "$last_detail"
echo "gz-acme-renew result=failed detail=$last_detail" >&2
exit 1
