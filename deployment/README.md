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

## Family room

The managed family conversation is room `!zeH0LfJ1UQUIIR1Zm0or2b843_84zsDIYH4qxw-kDew`. It is named `Family`, owned by `api30`, and has exactly the provisioned `api30` and `tcnowifi` accounts as joined members. The room was created empty with end-to-end encryption, shared history visibility, forbidden guest access, invite-only membership, private directory visibility, and federation disabled in the room creation event.

Run `just gz-family-room` to check these invariants and repair a missing membership. The provisioner obtains working access through unique temporary MAS compatibility sessions, performs ordinary Matrix client operations, logs out those sessions immediately, and confirms that their tokens no longer authenticate. Compatibility sessions do not currently have a configured automatic lifetime, so successful logout verification is mandatory. It does not read or change either account password, and it does not touch existing phone sessions or encryption recovery data. A mismatch in an immutable or security-sensitive room property fails instead of silently replacing the room.

Room membership does not provide encryption history by itself. Because this room is empty at provisioning time, both accounts can establish encryption on their actual phones before any family messages are sent. Do not claim that old history is recoverable until each account's client-side recovery and key backup have been exercised with the original phone unavailable.

### Isolated App Review room

Do not give an external reviewer a real family account or add a reviewer account to the Family room. Once a dedicated reviewer account has been approved and added to the private inventory by its owner, use the same provisioner with a separate one-member room and a different room name. Override all room variables in one Ansible invocation and leave the room ID empty only on the first run so the provisioner discovers or creates a single exact-name room:

```sh
ansible-playbook -i inventory/hosts deployment/provision-family-room.yml \
  --extra-vars '{"gz_family_room_id":"","gz_family_room_name":"App Review Demo","gz_family_room_owner_localpart":"<reviewer-localpart>","gz_family_room_member_localparts":["<reviewer-localpart>"]}'
```

Record the returned room ID in a private review-specific vars file before repeating the command. Use unique reviewer credentials, share them only through App Store Connect, and remove or lock the reviewer account after review. This path creates neither an enrollment service nor server-side recovery-secret escrow, and it grants no access to the real Family room.

### Current push status

At provisioning time Synapse had one HTTP pusher for `api30`, using the stock Element Android app identifier and the public Matrix.org push gateway. `tcnowifi` had no registered pusher. This proves only that one existing client registered a push route; the independently identified Android and iOS forks still need their own matching push credentials and gateway configuration before notification delivery can be claimed.
