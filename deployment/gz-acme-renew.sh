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
readonly served_ports="443 8448 5350 2357"

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

validate_served_certificates() {
    local installed_fingerprint port served_certificate served_fingerprint
    installed_fingerprint=$(/usr/bin/openssl x509 -in "$certificate" -noout -fingerprint -sha256) || return 1
    for port in $served_ports; do
        served_certificate=$(/usr/bin/mktemp "$status_dir/.served-$port.XXXXXX")
        if ! /usr/bin/timeout 10 /usr/bin/openssl s_client \
            -connect "127.0.0.1:$port" -servername "$domain" </dev/null 2>/dev/null \
            | /usr/bin/openssl x509 -out "$served_certificate" 2>/dev/null; then
            rm -f "$served_certificate"
            echo "gz-acme-renew served-port=$port result=unreachable" >&2
            return 1
        fi
        if ! /usr/bin/openssl x509 -in "$served_certificate" -noout -checkend 86400 >/dev/null; then
            rm -f "$served_certificate"
            echo "gz-acme-renew served-port=$port result=expires-within-one-day" >&2
            return 1
        fi
        served_fingerprint=$(/usr/bin/openssl x509 -in "$served_certificate" -noout -fingerprint -sha256) || {
            rm -f "$served_certificate"
            return 1
        }
        rm -f "$served_certificate"
        if [ "$served_fingerprint" != "$installed_fingerprint" ]; then
            echo "gz-acme-renew served-port=$port result=fingerprint-mismatch" >&2
            return 1
        fi
    done
    return 0
}

retry_registered_reload() {
    local check
    echo "gz-acme-renew action=retry-registered-reload"
    /etc/peacelove/tls-reload.sh || return 1
    /usr/local/sbin/matrix-tls-sync --refresh || return 1
    check=1
    while [ "$check" -le 5 ]; do
        /usr/bin/sleep 2
        if validate_served_certificates; then
            return 0
        fi
        check=$((check + 1))
    done
    return 1
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
        if [ "$result" = ok ]; then
            printf 'served_certificates=matched\n'
        else
            printf 'served_certificates=unverified\n'
        fi
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
            if validate_served_certificates || retry_registered_reload; then
                write_status ok disk-and-served-certificates-valid
                echo "gz-acme-renew result=ok certificate=$(certificate_expiry_epoch) served=matched"
                exit 0
            fi
            last_detail=served-certificate-validation-failed
        else
            last_detail=certificate-validation-failed
        fi
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
