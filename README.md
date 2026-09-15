# Pi-hole + Unbound, as code

[![CI](https://github.com/camercu/pihole/actions/workflows/ci.yml/badge.svg)](https://github.com/camercu/pihole/actions/workflows/ci.yml)

Infrastructure-as-code for a single Raspberry Pi running **Pi-hole** (DNS ad
blocking) in front of **Unbound** (an encrypted DNS-over-TLS forwarder). The
whole box is described declaratively so it can be rebuilt from a fresh SD card
by running one playbook.

## Design

Three layers, cleanly separated:

1. **OS provisioning** — flash Raspberry Pi OS Lite, enable SSH (done by hand /
   Raspberry Pi Imager).
2. **Host configuration + apps** — this repo's Ansible playbook: hostname,
   locale/timezone, packages, Unbound, Pi-hole, scheduled maintenance.
3. **Data** — blocklists, allowlists, local DNS records, all version-controlled
   in `group_vars` and role files.

**Bare-metal, not Docker.** The target is a Pi 2 B+ (ARMv7 32-bit, 1 GB RAM);
containers add overhead and 32-bit image risk it doesn't need. Ansible installs
Pi-hole and Unbound directly, the way the original `install.sh` did — just
idempotent and reproducible.

**Unbound is a DoT forwarder, not a root resolver.** It forwards over TLS to
Cloudflare Families / Quad9 / Google (see `unbound_forward_addrs`), preserving
upstream family-filtering and giving a local encrypted cache. SafeSearch is
enforced locally via CNAME redirects.

```
client → Pi-hole (:53, blocklists) → Unbound (:5335, DoT cache) → upstream resolvers
```

## Layout

```
shell.nix / .envrc          # nix dev env: ansible, ansible-lint, ruff, pytest, restic
justfile                    # task runner: `just deploy`, `just mirror`, `just adopt`,
                            #   `just lint`, `just test`, `just test-full`
ansible/
  ansible.cfg
  inventory.yml             # the Pi: host, ssh user
  site.yml                  # runs the roles in order
  verify.yml                # post-deploy smoke test (run against the live host)
  mirror.yml                # make the config files match what the box holds
  adopt.yml                 # hand captured entries over to the reconciler
  group_vars/all/
    defaults.yml            # generic per-site facts (overridden by local.yml)
    main.yml                # cross-role interface: unbound endpoint, password
    vault.yml               # gitignored: encrypted admin/API + restic passwords
    local.yml               # gitignored: connection + per-site facts (see below)
  roles/
    common/                 # hostname, locale, timezone, packages, /etc/hosts, ssh keys
    unbound/                # install + config templates, root hints, SafeSearch
    pihole/                 # unattended install, upstream→unbound, adlists/allowlists
    alerting/               # OnFailure= notifier for the scheduled jobs
    maintenance/            # gravity/root-hints/pihole refresh, reboot, unattended-upgrades
    backup/                 # weekly Teleporter export -> restic on the NAS (opt-in)
    hardening/              # firewall, drop unused services, force HTTPS admin, no root SSH
    verify/                 # smoke checks: DNS resolves + blocks, unbound, admin UI
tests/                      # pytest: fast unit tests + opt-in real-container integration
  integration/              # end-to-end tests against a real Pi-hole in docker/podman
```

## Quick start (one command)

For a fresh Pi handed to anyone — including a non-technical person:

1. **Flash the SD card** with Raspberry Pi Imager. In its settings (gear icon):
   set hostname `pihole`, enable SSH, and set a username + password (or your
   SSH key). Boot the Pi and connect it to the network.
2. **Run the setup command** from this repo:

   ```bash
   ./setup.sh
   ```

No Nix or Ansible install needed — on a plain Mac with Python, `setup.sh`
bootstraps [`uv`](https://docs.astral.sh/uv/) and runs Ansible in an isolated
environment automatically. (If you already have Nix, it uses that instead.)

That's it. On the first run it asks for:

- a **vault passphrase** (encrypts your saved passwords),
- a **Pi-hole admin password** (also used for the API),
- **how to reach the Pi** (address, SSH user),

stores them locally (never committed), then provisions everything. Re-runs
reuse the saved answers and go straight to provisioning.

Everyone who uses this repo gets their **own** passwords — the answers live in
gitignored files (`ansible/.vault-pass`, `group_vars/all/{vault,local}.yml`), so
nothing personal is shared when the repo is.

## Prerequisites (manual / advanced)

`./setup.sh` handles the below for you; reach for these only to run Ansible
directly:

- [Nix](https://nixos.org/download) — all tooling runs through `nix-shell`.
- A Pi reachable over SSH; connection set in `group_vars/all/local.yml` (copy
  `local.yml.example`).
- Vault passphrase in `ansible/.vault-pass` (see **Secrets**).

With [direnv](https://direnv.net/): `direnv allow` loads the env (and the vault
key) automatically. Otherwise prefix commands with `nix-shell --run '…'`.

```bash
# Full rebuild (same as ./setup.sh once configured):
nix-shell --run 'just deploy'
nix-shell --run 'cd ansible && ansible-playbook site.yml'   # the same thing

# Preview without changing anything:
nix-shell --run 'cd ansible && ansible-playbook site.yml --check --diff'

# Capture changes made by hand in the admin UI into the config files,
# then (after committing the diff) let the reconciler manage them:
nix-shell --run 'just mirror'
nix-shell --run 'just adopt'

# One role only (tags: common, unbound, pihole, maintenance):
nix-shell --run 'cd ansible && ansible-playbook site.yml --tags pihole'

# Static checks:
nix-shell --run 'cd ansible && ansible-playbook --syntax-check site.yml'
nix-shell --run 'cd ansible && ansible-lint'

# Safety nets — lint helper scripts, run their unit tests, lint playbooks:
nix-shell --run 'just lint'                     # ruff + ansible-lint
nix-shell --run 'just test'                     # fast unit tests
nix-shell --run 'just test-full'                # + real-container integration tests
nix-shell --run 'pre-commit run --all-files'   # lint + unit tests at once
nix-shell --run 'pre-commit install'           # run them on every git commit
```

## Tests

Two layers, both run in [CI](.github/workflows/ci.yml) on every push:

- **Unit tests** cover the pure decision logic in the helper scripts (list
  diffing, group membership, DNS-packet parsing, restic argv). Fast, no
  network: `just test`.
- **Integration tests** start a **real Pi-hole v6 container** and drive the
  *deployed* scripts against its live FTL API — proving the list reconciler,
  the backup export/restore round trip, and the smoke checker actually work
  against Pi-hole, not a mock. They are opt-in (`PIHOLE_IT=1`) and need
  **docker or podman** on `PATH`; `just test-full` runs them (auto-skipped by
  `just test` when the runtime is absent).

## Changing configuration

**Blocklists / allowlists** are plain, commented text files under
`ansible/roles/pihole/files/` — edit them directly. These apply network-wide
(Pi-hole's default group):

- `adlists.txt` — blocklists (gravity), one URL per line
- `allow.list` — allowed domains, exact or regex, one per line
- `allowlist-urls.txt` — remote allowlists to fetch and allow

**Groups** let you block extra things for *some* devices only. Each subdirectory
of `ansible/roles/pihole/files/groups/` is a Pi-hole group (the directory name is
the group name), holding up to three files:

- `block.list` — domains blocked for this group, exact or regex, one per line
- `adlists.txt` — remote blocklists applied to this group
- `clients.txt` — the group's devices (IP / MAC / hostname / subnet), one per line

Deleting a group's directory removes the group from the Pi on the next
`just deploy`: the deployed copy is brought back into line with this tree rather
than only added to, so a group stops existing when nothing here describes it.

A device listed in a group's `clients.txt` joins that group **and** the default
group, so it keeps normal ad/threat blocking and additionally gets the group's
block lists. A shipped **`kids`** group blocks social media + AI chatbots; it
affects nobody until you add your kids' devices to `groups/kids/clients.txt`.

Other settings live with the role that owns them (each `roles/<role>/defaults/
main.yml`), which ship **generic defaults** so the playbook runs anywhere.
Cross-role wiring (the unbound endpoint, the password interface) is in
`group_vars/all/main.yml`:

- **Upstream resolvers** — `unbound_forward_addrs` (`roles/unbound/defaults/`)

**Per-site facts** — anything describing *your* network — belong in the
gitignored `group_vars/all/local.yml`, which overrides the role defaults so you
never edit tracked files (see `local.yml.example` for the full shape):

- **LAN hosts / `/etc/hosts`** — `lan_hosts` (also served as unbound
  split-horizon A records)
- **Firewall subnet** — `hardening_lan_subnet`
- **Timezone / locale** — `system_timezone`, `system_locale`
- **Backup NAS** — `backup_nas_host`

Edit, re-run the playbook (or `./setup.sh`), done. The pihole role reconciles
lists into Pi-hole through its **REST API** (`pihole_deploy.py`): it adds
what's missing, removes what it previously added but is no longer listed, and
rebuilds gravity only when adlists actually change. It's declarative and
idempotent — a no-op run makes no changes. A remote allowlist that fails to
download is never treated as "removed", so a network blip can't wipe entries. If
you also add an entry (adlist, domain, client, or group) **by hand** in the
admin UI that a config file already manages, it's skipped with a warning and
the run exits non-zero so you notice — remove the hand-added copy to let the
role manage it.

"Managed by this role" is not decided by the `managed by ansible` comment
alone — that box is free text the admin UI lets anyone type, so typing it on
a hand-added row would otherwise hand that row to the next deploy for
deletion. The role also keeps `.manifest.json` next to the config files on
the Pi, recording what it itself created last run; a row only deletes when
the comment and the manifest agree.

Ownership is total: a file listing an entry says which groups it belongs to *and*
that it is switched on. Toggling a managed row off in the admin UI is undone on
the next run, because nothing else would put it back — mirroring skips rows the
reconciler owns, so a managed block left off would survive every run and every
rebuild while the files went on claiming it was in force. To switch one off for
good, delete it in the admin UI and run `just mirror` — the deletion is
captured, so you never hand-edit the files to undo something you did in the UI.

### Mirroring changes made in the admin UI

The reconciler pushes files into Pi-hole and leaves entries added by hand alone,
so a blocklist you add in the UI works but no file records it — a rebuild from a
fresh SD card loses it. `just mirror` closes that loop: it reads live Pi-hole
state and writes what the config format can express into
`ansible/roles/pihole/files/`, ready to review with `git diff` and commit. It
never changes the Pi.

Capture runs both ways, so the admin UI can be where you work. A file the
mirror owns ends up listing what the box actually holds: entries you added appear,
entries you deleted go, and your comments, blank lines and ordering are left
exactly where they were. Only the files the mirror can route into are touched —
`allowlist-urls.txt` names remote lists to fetch rather than entries Pi-hole
holds, so it is never pruned.

A file only loses a line when the box still holds something else that file
lists. An entry a file names and the box does not hold is ambiguous on its own —
someone deleted it, or this box was never given it — and the two are told apart
per file, not per entry: a Pi that ever took this file still holds part of it,
while a Pi that never did holds none of it. So mirroring against a box the
committed files were never deployed to leaves them alone rather than emptying
them, and names each file it left alone with the count involved. The one
case that misreads is a file whose every entry really was deleted in the admin
UI; the mirror declines that too (exit 5), and `just mirror force=true` is how
you say it was deliberate.

Domains fetched from `allowlist-urls.txt` are pushed to Pi-hole under a comment
distinct from `allow.list`'s own (`managed by ansible (fetched)`), so the
mirror leaves them alone entirely rather than forking the remote list into
`allow.list`. Deleting an entry from `allow.list` also no longer waits on
every URL in `allowlist-urls.txt` loading first — the two reconcile
independently.

`git diff` is still the gate — nothing reaches the Pi until you commit and run
`just deploy`.

An entry is captured only when reconciling from the file it lands in would
reproduce that entry's current group set exactly. The UI can say things the
config cannot — an allowlist scoped to one group, a device outside the default
group, a disabled row — and capturing those anyway would change what Pi-hole
blocks, so the mirror names each one with the reason and exits 4 instead. That
does not fail the run: the files it could capture were still written, and a
check that stays red for something with no fix is one people learn to ignore.
Record those another way, or accept that a rebuild won't restore them.

A captured entry still carries its hand-added comment on the box, so the next
`site.yml` run would report it as a collision. Deploy the committed files first
(`just deploy`, or `--tags pihole` for the pihole role alone) — `just adopt`
refuses to run while the Pi is reconciling from something other than what you
just reviewed, since an entry only the repo records is one the next reconcile
would delete. `just adopt` then finishes the job: it hands every entry the
config files now record over to the reconciler by
rewriting that comment. Nothing is deleted or re-resolved — the row stays put
and only changes hands — and an entry no file records is left alone, so adopting
can't turn into a way to lose settings.

The loop, then, is: change what you like in the admin UI, `just mirror`, review
the diff and commit, `just deploy`, `just adopt`. The deploy in the middle is
not optional — `just adopt` refuses to run without it, since an entry only the
repo records is one the next reconcile would delete.

`verify.yml` runs the same comparison and fails when the box carries a setting
no config file records — so drift surfaces on a routine health check rather than
on the day the SD card dies. Settings the config format cannot express are
reported there but don't fail it: a check that stays red for something with no
fix is one people learn to ignore.

## Secrets (Ansible Vault)

`./setup.sh` creates these for you; this section is for editing them later.

The Pi-hole admin / API password is stored **encrypted** in the gitignored
`group_vars/all/vault.yml` as `vault_pihole_web_password`; `main.yml` reads it
via `pihole_web_password`. The passphrase that decrypts it lives in the
(gitignored) `ansible/.vault-pass`. Neither leaves your machine — each user of
the repo has their own.

`direnv` auto-exports `ANSIBLE_VAULT_PASSWORD_FILE` when `ansible/.vault-pass`
exists, so Ansible commands just work. Without direnv, add `--ask-vault-pass`.

```bash
# Change the stored password, then re-run so `pihole setpassword` applies it:
nix-shell --run 'cd ansible && ansible-vault edit group_vars/all/vault.yml'
nix-shell --run 'cd ansible && ansible-playbook site.yml --tags pihole'

# Rotate the passphrase itself:
nix-shell --run 'cd ansible && ansible-vault rekey group_vars/all/vault.yml'
```

The same password is also the API credential baked into the backup env file, so
if backups are enabled re-run the `backup` tag too (`--tags pihole,backup`) to
keep the Teleporter export authenticating.

⚠️ Back up the **passphrase** (password manager) — lose it and the encrypted
file is unrecoverable.

## Backups

The `backup` role exports a Pi-hole **Teleporter** bundle (all config: adlists,
allow/deny, DHCP, settings) via the API and stores it weekly in a **restic**
repository on your NAS (`backup_nas_host`) over SFTP — encrypted, deduplicated,
incremental. A `pihole-backup.timer` runs it Sunday 04:30; retention keeps 8
weekly snapshots.

It's **off by default** (`backup_enabled: false`) so the playbook stays green
until the NAS is set up. To enable:

1. **Give the Pi SSH access to the NAS** — the Pi's root user must be able to
   `ssh <nas_user>@<backup_nas_host>` non-interactively (install a key).
2. **Add the restic repo password to the vault:**

   ```bash
   nix-shell --run 'cd ansible && ansible-vault edit group_vars/all/vault.yml'
   # add:  vault_restic_password: "a-strong-passphrase"
   ```

3. **Fill in the NAS details** in `group_vars/all/local.yml`: `backup_nas_host`,
   `backup_nas_user`, `backup_nas_path`. Then set `backup_enabled: true` in
   `roles/backup/defaults/main.yml` (that toggle isn't per-site).
4. **Run the playbook.** It installs restic, `restic init`s the repo if needed,
   and enables the weekly timer.

Restore (on a fresh Pi, after `./setup.sh`): pull the latest snapshot with
`restic restore latest --target /tmp/restore`, then import the `.zip` via the
Pi-hole admin UI (Settings → Teleporter) or the API. A dead SD card becomes a
flash → `./setup.sh` → import recovery.

Run a backup on demand: `sudo systemctl start pihole-backup.service`.

## Verifying a deploy

A green `site.yml` run proves Ansible applied the config — not that DNS actually
works. `verify.yml` checks the running box end-to-end and fails loudly if
anything is wrong:

```bash
nix-shell --run 'cd ansible && ansible-playbook verify.yml'
```

It asserts that `pihole-FTL` and `unbound` are running, gravity is loaded and
blocking is on, a normal domain resolves, a known ad domain is sinkholed,
unbound answers directly on `:5335`, and the admin UI responds over HTTPS. The
probe domains are overridable (`roles/verify/defaults/main.yml`). The same
checks (`roles/verify/files/pihole_smoke.py`) are exercised against a real
container in CI, so the logic is trusted.

## Alerting

The scheduled maintenance and backup jobs would otherwise fail silently. The
`alerting` role wires an `OnFailure=` handler into each: a failed run is always
logged to the journal, and — if you set a webhook — a report is pushed off-box.
Point `alerting_webhook_url` (in `group_vars/all/local.yml`) at e.g. an
[ntfy](https://ntfy.sh) topic; leave it empty for journal-only. If the URL
embeds a token, put it in the vault instead.

## Security

The `hardening` role applies host security that survives rebuilds — chosen for
zero/low usability cost:

- **Host firewall** (`ufw`): default-deny inbound, allowing only the LAN
  (`hardening_lan_subnet`) to SSH (22), DNS (53), admin HTTPS (443), and mDNS
  (5353).
- **Removes `rpcbind`** (port 111) — unused without NFS; a known amplification
  vector.
- **Disables Pi-hole FTL's NTP server** (port 123); the clock still syncs via
  `systemd-timesyncd`.
- **Forces HTTPS** for the admin UI — plain HTTP is bound to loopback only (so
  the local reconciler API still works); LAN admin must use `https://`.
- **`PermitRootLogin no`** — log in as the normal user and `sudo`.
- **Key-only SSH** (`PasswordAuthentication no`) — enforced *once an SSH key is
  provisioned* (`authorized_ssh_keys` non-empty). Left enabled otherwise so a
  password-bootstrap user isn't locked out; add your key, re-run, and it flips.

Already in place by design: Pi-hole answers only the local subnet (not an open
resolver), Unbound does DNSSEC validation with hardening flags, the upstream is
DNS-over-TLS, and the admin password is set. Security patches are applied by
`unattended-upgrades`.

Change the allowed subnet via `hardening_lan_subnet` in `roles/hardening/defaults/main.yml`.

## Troubleshooting

- **`ansible-playbook` can't reach the Pi** — check `ansible_host`/`ansible_user`
  in `local.yml`; `ssh <user>@<host>` should work first. After hardening flips
  to key-only SSH, password auth is off (see **Security**).
- **Vault decryption errors** — `ansible/.vault-pass` is missing or wrong; with
  `direnv` it's auto-loaded, otherwise add `--ask-vault-pass`.
- **`verify.yml` reports a failing check** — read the `[FAIL]` line. Gravity not
  populated → run `--tags pihole` (or `pihole -g` on the box); a domain not
  resolving → check unbound (`systemctl status unbound`, `unbound-checkconf`);
  admin HTTPS down → check `pihole-FTL`.
- **`just deploy` exits non-zero with a collision warning** — a list entry, or
  a group, was also added by hand in the admin UI under a name a config file
  already uses. Remove the hand-added copy so the role can manage it; that
  group's own config stays undeployed until you do.
- **`just mirror` says it left entries alone (exit 5)** — the box holds nothing
  else that file lists, so the entries missing from it were never deleted there;
  most likely you are mirroring a Pi the committed files were never deployed to.
  Run `just deploy` first. If you really did delete every entry in that file in
  the admin UI, say so: `just mirror force=true`.
- **`just mirror` refuses with "already have uncommitted changes" (exit 6)** —
  a hand-edit to a config file this run would also write is not committed
  yet. Commit or stash it first; merging into a dirty tree would make your
  edit and the mirror's capture indistinguishable in `git diff`, and could
  overwrite what you had not yet pushed to the box.
- **`just deploy` warns that a config file is not there** — a top-level file
  (`adlists.txt`, `allow.list`, `allowlist-urls.txt`) is missing, so this run
  cannot know what it would have listed and removes nothing for that kind.
  Restore the file, or add it empty if you meant it to list nothing.
- **`just deploy` warns that `groups/` is not there** — the whole per-group
  tree is missing, so this run cannot know what any group, deny list or
  client should be and removes none of them. Restore `ansible/roles/pihole/
  files/groups/`, even empty, if you meant every group to be gone.
- **`verify.yml` reports drift** — Pi-hole carries settings no config file
  records. `just mirror` writes them into the files; review with `git diff`
  and commit.
- **A scheduled job failed** — `systemctl list-timers`, then
  `journalctl -u maint-<job>.service` (or `pihole-backup.service`). With a
  webhook configured you'll have been alerted (see **Alerting**).

## Recovery from scratch

A dead SD card is a non-event because the whole box is code:

1. Flash Raspberry Pi OS Lite, enable SSH (Raspberry Pi Imager).
2. `./setup.sh` — reprovisions everything from this repo.
3. If backups were enabled, restore config: `restic restore latest --target
   /tmp/restore`, then import the `.zip` (admin UI → Settings → Teleporter).
4. `ansible-playbook verify.yml` to confirm the box is healthy.
