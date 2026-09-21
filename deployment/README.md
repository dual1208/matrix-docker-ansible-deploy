<!-- SPDX-FileCopyrightText: 2026 dual1208 -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# gz IP deployment

This private two-phone deployment uses `https://8.163.2.191` with Synapse, Matrix Authentication Service, MatrixRTC (LiveKit and its authorization service), and Traefik. The deployment is intentionally bound to this IP as its Matrix identity. Its container PostgreSQL is separate from the existing host PostgreSQL service.

The public configuration is `gz-vars.yml`. The active inventory links to it from `inventory/host_vars/gz/vars.yml`. Generated secrets and the `tcnowifi` and `api30` account passwords are in `inventory/host_vars/gz/secrets.yml`, which is excluded from Git and restricted to the local user. Preserve that file and the server's `/matrix` data; regenerating secrets is not an upgrade procedure.

The parent workspace's `justfile` provides `server-check`, `server-setup`, and `server-verify`. Ansible dependencies are pinned in `requirements.txt`; install them with `uv pip install --python /Users/xie/IMcalling/.venv/bin/python -r deployment/requirements.txt` after creating that environment. External roles are pinned by the upstream `requirements.yml`.

The host already had a valid Let's Encrypt IP certificate under `/etc/peacelove/tls`, managed by `/root/.acme.sh`. Matrix reuses that certificate via `matrix-tls-sync.sh`. When certificate files change or a served-certificate mismatch needs repair, the sync helper refreshes Traefik through its watched dynamic provider file; it does not stop or start the proxy. The existing application retains its original hot-reload command. On 2026-09-19, an actual HTTP-01 issuance succeeded, and both services received the new certificate, expiring 2026-09-25 16:42:55 UTC. The server timezone is Asia/Shanghai. A cron fallback runs `/usr/local/sbin/gz-acme-renew` at 00:30, 06:30, 12:30, and 18:30 local time; a persistent systemd timer runs the same helper five minutes later. The helper uses an exclusive lock, limits each acme.sh attempt to five minutes, and retries failures twice. It validates the installed IP SAN, chain, and remaining lifetime, then requires the same leaf fingerprint and lifetime from ports 443, 8448, 5350, and 2357. A mismatch retries the registered reload hook without forcing issuance. Nonsecret status is recorded in `/var/lib/gz-acme-renew/status`. The ARI-selected renewal is due at 2026-09-22 17:11:59 CST, so the first cron check after it is 18:30 CST (10:30 UTC). Renewal uses acme.sh standalone mode: TCP 80 has no persistent listener and is bound only briefly while HTTP-01 validation runs. `install-tls.yml` preserves the earlier ACME configuration, saves standalone mode, and registers the combined reload hook.

For a fresh restoration, first ensure TCP 80 is publicly reachable but has no persistent listener, then issue from the server with acme.sh's temporary standalone listener:

```sh
/root/.acme.sh/acme.sh --issue --server letsencrypt --cert-profile shortlived --keylength ec-256 --days 3 --standalone -d 8.163.2.191
```

Run `deployment/install-tls.yml` again to install the issued certificate and retain both reload commands. Do not force reissue as a routine deployment step.

The iOS fork uses the static public MAS client `01M2VM6HEE7G54S8RFEJEFK7DT` with issuer `https://8.163.2.191/auth/` and redirect `com.dual1208.elementx:/oauth`. It needs no client secret or public DNS domain.

Docker Hub's direct route from this host timed out during initial installation. Image pulls can temporarily use a reverse SOCKS tunnel through the Mac:

```sh
ssh -F /dev/null -i /Users/xie/.ssh/m4 -p 721 -o ExitOnForwardFailure=yes -N -T -R 127.0.0.1:18080 root@8.163.2.191
```

With that tunnel running, a temporary Docker systemd drop-in can set `HTTP_PROXY` and `HTTPS_PROXY` to `socks5h://127.0.0.1:18080`, followed by a Docker restart. Remove the drop-in and restart Docker when pulls finish, then run the playbook's `start` tag to restore its managed services. Existing cached images do not require the tunnel for application operation. This route does not proxy application messages or call media.

The host uses TCP 443 for HTTPS, TCP 8448 for Matrix OpenID verification, TCP 7881 and UDP 7882 for RTC, UDP 3479 and TCP 5350 for LiveKit TURN, and UDP 30000–30020 for TURN relay traffic. TCP 80 is reserved exclusively for acme.sh's temporary HTTP-01 listener and must otherwise stay closed; it serves no redirect, download, or application traffic. HTTPS and federation entry points also support QUIC on UDP 443/8448. `verify.py` checks TLS, public discovery, MAS, JWT health, TURN/UDP binding, TCP listeners, and that TCP 80 has no persistent service. `just gz-acme-verify` additionally checks the saved renewal mode, both schedulers, locked-helper status freshness, SAN, chain, and certificate lifetime; retry it if it happens to overlap the brief renewal window. Inspect the latest run with `systemctl status gz-acme-renew.service` and `cat /var/lib/gz-acme-renew/status`. A passing result alone does not establish a successful phone-to-phone call.

On 2026-09-19, Alibaba Cloud CLI 3.5.1 with the existing `tyson` OAuth profile confirmed the Guangzhou instance and its dedicated security group. Six inbound rules were added: TCP 5350, 7881, 8448 and UDP 3479, 7882, 30000–30020. All ten public endpoint checks then passed. The original and resulting security-group snapshots are kept privately in `var/security-group-before.json` and `var/security-group-after.json`; OAuth credentials remain outside this repository. Optional QUIC ports were not added.

Repository entry points are `just gz-check`, `just gz-deploy`, and `just gz-verify`. Set `GZ_ANSIBLE` and `GZ_PYTHON` to the installed virtualenv executables, or put its `bin` directory on `PATH`. The parent workspace does this automatically. Deployment uses the existing inventory and account secrets; preserve them when moving the checkout.

## Managed rooms

The server provisions three isolated, private, unencrypted rooms:

- `家庭群` (`!_-bzJ4bmo3TT-VHRkkaBkDyPch8zZu_BTPkHRIpaB44`) contains only `xie`, `tyson`, and `lawyerche`.
- `测试群` (`!xyB-SrePbfrBbhD3k-SOOnt_hiunqsfrXk7syYnTA0o`) contains only the development accounts `api30` and `tcnowifi`.
- `审核演示群` (`!4xPNX-nCYec0FKHt83DOuQxOpnwElo7uD4Ldnr5yBQk`) contains only the private `appreview` account.

All three have shared history, forbidden guest access, invite-only membership, private directory visibility, and federation disabled in the room creation event. They deliberately have no `m.room.encryption` state event: transport remains protected by HTTPS, but the server administrator can read stored messages and media. The earlier encrypted `Family` room and its accounts/history remain untouched.

Run `just gz-family-room` to verify and repair these rooms. The provisioner checks every security invariant before membership changes, never sends a message, uses temporary MAS compatibility sessions for ordinary Matrix client operations, logs out each session, and confirms its token no longer authenticates. It assigns each member a room through global account data type `io.familychat.assigned_room` with content `{"room_id": "!opaqueRoomId"}`. Both native clients read this mapping after sync and fail closed when it is absent or malformed; no room ID belongs in the binary.

Run `just gz-call-power-levels` to allow ordinary members to publish the two
MatrixRTC membership state event types required by current and legacy clients.
The repair adds only `m.call.member: 0` and
`org.matrix.msc3401.call.member: 0` to each room's existing `events` power-level
map. It preserves the administrator, default state, invitation, moderation,
notification, and all unrelated event levels. Before its first repair it uses
the ordinary `tcnowifi` member, rather than the `api30` room owner, to prove the
existing `403 M_FORBIDDEN` in the isolated development room; afterward it
proves the same empty self-membership event succeeds there. Maintenance
sessions are issued without passwords, revoked immediately, and checked for a
`401` response after logout. The probe never joins a new user or sends a room
message.

The real family accounts must never be logged into development phones or used for test messages. Development accounts have no membership in `家庭群`, and the App Review account has membership only in `审核演示群`. Reviewer credentials remain in the ignored mode-0600 inventory and may be shared only through App Store Connect after the owner approves them.

## Public support pages and hosted UI

Run `just gz-family-public` to publish and verify the static support and privacy pages at `https://8.163.2.191/family/support/` and `https://8.163.2.191/family/privacy/` through the existing TLS/static-files service. Run `just gz-mas-branding` to install the pinned Chinese MAS branding override and restart only MAS. Traefik forces `zh-Hans`, while the override also makes the English fallback Chinese, labels the service `家庭聊天`, removes upstream product names and public diagnostics from visible pages, and links the footer to the local privacy notice. Element Call web hosting is disabled; public discovery advertises only this server's MAS and self-hosted LiveKit JWT service, with no `call.element.io` URL.

Synapse usage reporting is disabled and its Sentry DSN is explicitly empty. No analytics, crash-reporting, metrics-export, or external monitoring service is enabled by this deployment.

## Current push status

The server-side Sygnal push gateway is disabled, and neither mobile repository contains an FCM service-account configuration, Apple push signing key, or matching self-hosted gateway credentials. The obsolete stock Element Android pusher which targeted Matrix.org was removed from `api30` without revoking its phone session. Locked-screen notification or ringing delivery remains blocked until the owner supplies platform credentials.

When credentials exist, store the `gz_push_*` values only in the ignored mode-0600 secrets inventory and run `just gz-push-prepare`. The recipe writes provider keys as mode-0600 files and installs a Sygnal definition at the local `/push` path, with metrics, tracing, and Sentry disabled. It deliberately does not start the service; first update both native clients with their final app IDs, matching FCM/APNs configuration, and the local gateway URL, then validate delivery before starting it.
