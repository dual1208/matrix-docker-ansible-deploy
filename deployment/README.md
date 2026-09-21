<!-- SPDX-FileCopyrightText: 2026 dual1208 -->
<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# gz IP deployment

This private two-phone deployment uses `https://8.163.2.191` with Synapse, Matrix Authentication Service, MatrixRTC (LiveKit and its authorization service), and Traefik. The deployment is intentionally bound to this IP as its Matrix identity. Its container PostgreSQL is separate from the existing host PostgreSQL service.

The public configuration is `gz-vars.yml`. The active inventory links to it from `inventory/host_vars/gz/vars.yml`. Generated secrets and the `tcnowifi` and `api30` account passwords are in `inventory/host_vars/gz/secrets.yml`, which is excluded from Git and restricted to the local user. Preserve that file and the server's `/matrix` data; regenerating secrets is not an upgrade procedure.

The parent workspace's `justfile` provides `server-check`, `server-setup`, and `server-verify`. Ansible dependencies are pinned in `requirements.txt`; install them with `uv pip install --python /Users/xie/IMcalling/.venv/bin/python -r deployment/requirements.txt` after creating that environment. External roles are pinned by the upstream `requirements.yml`.

The host already had a valid Let's Encrypt IP certificate under `/etc/peacelove/tls`, managed by `/root/.acme.sh`. Matrix reuses that certificate via `matrix-tls-sync.sh`. The sync helper restarts only Matrix's reverse proxy when the certificate changes; the existing application retains its original hot-reload command. On 2026-09-19, an actual HTTP webroot issuance succeeded, and both services received the new certificate, expiring 2026-09-25 16:42:55 UTC. The existing ACME cron runs every six hours, with the next renewal selected for 2026-09-22. Renewal now uses `/matrix/static-files/public`, because Matrix owns port 443. `install-tls.yml` preserves the original ACME configuration as `8.163.2.191.conf.before-matrix` and registers the combined reload hook.

For a fresh restoration, start the services, verify a unique test file under `http://8.163.2.191/.well-known/acme-challenge/` is publicly reachable, then configure webroot issuance on the server:

```sh
/root/.acme.sh/acme.sh --issue --force --server letsencrypt --cert-profile shortlived --keylength ec-256 --days 3 -d 8.163.2.191 -w /matrix/static-files/public
```

Run `deployment/install-tls.yml` again to install the issued certificate and retain both reload commands. Do not force reissue as a routine deployment step.

The iOS fork uses the static public MAS client `01M2VM6HEE7G54S8RFEJEFK7DT` with issuer `https://8.163.2.191/auth/` and redirect `com.dual1208.elementx:/oauth`. It needs no client secret or public DNS domain.

Docker Hub's direct route from this host timed out during initial installation. Image pulls can temporarily use a reverse SOCKS tunnel through the Mac:

```sh
ssh -F /dev/null -i /Users/xie/.ssh/m4 -p 721 -o ExitOnForwardFailure=yes -N -T -R 127.0.0.1:18080 root@8.163.2.191
```

With that tunnel running, a temporary Docker systemd drop-in can set `HTTP_PROXY` and `HTTPS_PROXY` to `socks5h://127.0.0.1:18080`, followed by a Docker restart. Remove the drop-in and restart Docker when pulls finish, then run the playbook's `start` tag to restore its managed services. Existing cached images do not require the tunnel for application operation. This route does not proxy application messages or call media.

The host uses TCP 80/443 for HTTP/HTTPS, TCP 8448 for Matrix OpenID verification, TCP 7881 and UDP 7882 for RTC, UDP 3479 and TCP 5350 for LiveKit TURN, and UDP 30000–30020 for TURN relay traffic. HTTPS and federation entry points also support QUIC on UDP 443/8448. `verify.py` checks TLS, public discovery, MAS, JWT health, TURN/UDP binding, and TCP listeners; a passing result alone does not establish a successful encrypted phone-to-phone call.

On 2026-09-19, Alibaba Cloud CLI 3.5.1 with the existing `tyson` OAuth profile confirmed the Guangzhou instance and its dedicated security group. Six inbound rules were added: TCP 5350, 7881, 8448 and UDP 3479, 7882, 30000–30020. All ten public endpoint checks then passed. The original and resulting security-group snapshots are kept privately in `var/security-group-before.json` and `var/security-group-after.json`; OAuth credentials remain outside this repository. Optional QUIC ports were not added.

Repository entry points are `just gz-check`, `just gz-deploy`, and `just gz-verify`. Set `GZ_ANSIBLE` and `GZ_PYTHON` to the installed virtualenv executables, or put its `bin` directory on `PATH`. The parent workspace does this automatically. Deployment uses the existing inventory and account secrets; preserve them when moving the checkout.

## Managed rooms

The server provisions three isolated, private, unencrypted rooms:

- `家庭群` (`!_-bzJ4bmo3TT-VHRkkaBkDyPch8zZu_BTPkHRIpaB44`) contains only `xie`, `tyson`, and `lawyerche`.
- `测试群` (`!xyB-SrePbfrBbhD3k-SOOnt_hiunqsfrXk7syYnTA0o`) contains only the development accounts `api30` and `tcnowifi`.
- `审核演示群` (`!4xPNX-nCYec0FKHt83DOuQxOpnwElo7uD4Ldnr5yBQk`) contains only the private `appreview` account.

All three have shared history, forbidden guest access, invite-only membership, private directory visibility, and federation disabled in the room creation event. They deliberately have no `m.room.encryption` state event: transport remains protected by HTTPS, but the server administrator can read stored messages and media. The earlier encrypted `Family` room and its accounts/history remain untouched.

Run `just gz-family-room` to verify and repair these rooms. The provisioner checks every security invariant before membership changes, never sends a message, uses temporary MAS compatibility sessions for ordinary Matrix client operations, logs out each session, and confirms its token no longer authenticates. It assigns each member a room through global account data type `io.familychat.assigned_room` with content `{"room_id": "!opaqueRoomId"}`. Both native clients read this mapping after sync and fail closed when it is absent or malformed; no room ID belongs in the binary.

The real family accounts must never be logged into development phones or used for test messages. Development accounts have no membership in `家庭群`, and the App Review account has membership only in `审核演示群`. Reviewer credentials remain in the ignored mode-0600 inventory and may be shared only through App Store Connect after the owner approves them.

## Public support pages and hosted UI

Run `just gz-family-public` to publish and verify the static support and privacy pages at `https://8.163.2.191/family/support/` and `https://8.163.2.191/family/privacy/` through the existing TLS/static-files service. Matrix Authentication Service receives `Accept-Language: zh-Hans,zh;q=0.9` from the local Traefik route so its hosted login pages select Simplified Chinese. Element Call web hosting is disabled; public discovery advertises only this server's MAS and self-hosted LiveKit JWT service, with no `call.element.io` URL.

Synapse usage reporting is disabled and its Sentry DSN is explicitly empty. No analytics, crash-reporting, metrics-export, or external monitoring service is enabled by this deployment.

## Current push status

The server-side Sygnal push gateway is disabled, and neither mobile repository contains an FCM service-account configuration, Apple push signing key, or matching self-hosted gateway credentials. The obsolete stock Element Android pusher which targeted Matrix.org was removed from `api30` without revoking its phone session. Locked-screen notification or ringing delivery remains blocked until the owner supplies platform credentials.

When credentials exist, store the `gz_push_*` values only in the ignored mode-0600 secrets inventory and run `just gz-push-prepare`. The recipe writes provider keys as mode-0600 files and installs a Sygnal definition at the local `/push` path, with metrics, tracing, and Sentry disabled. It deliberately does not start the service; first update both native clients with their final app IDs, matching FCM/APNs configuration, and the local gateway URL, then validate delivery before starting it.
