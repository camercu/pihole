# Pi-hole + Unbound, as code

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
client → Pi-hole (:53, blocklists) → Unbound (:5553, DoT cache) → upstream resolvers
```

## Layout

```
shell.nix / .envrc          # nix dev env: ansible + ansible-lint (+ sshpass)
ansible/
  ansible.cfg
  inventory.yml             # the Pi: host, ssh user
  site.yml                  # runs the four roles in order
  group_vars/all.yml        # single source of truth: hosts, upstreams, lists
  roles/
    common/                 # hostname, locale, timezone, packages, /etc/hosts, ssh keys
    unbound/                # install + config templates, root hints, SafeSearch
    pihole/                 # unattended install, upstream→unbound, adlists/allowlists
    maintenance/            # cron: gravity/root-hints/apt/self-update refresh, reboot
    backup/                 # weekly Teleporter export -> restic on the NAS (opt-in)
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
nix-shell --run 'cd ansible && ansible-playbook site.yml'

# Preview without changing anything:
nix-shell --run 'cd ansible && ansible-playbook site.yml --check --diff'

# One role only (tags: common, unbound, pihole, maintenance):
nix-shell --run 'cd ansible && ansible-playbook site.yml --tags pihole'

# Static checks:
nix-shell --run 'cd ansible && ansible-playbook --syntax-check site.yml'
nix-shell --run 'cd ansible && ansible-lint'
```

## Changing configuration

**Blocklists / allowlists** are plain, commented text files under
`ansible/roles/pihole/files/` — edit them directly:

- `adlists.txt` — blocklists (gravity), one URL per line
- `allow.list` — allowed domains, exact or regex, one per line
- `allowlist-urls.txt` — remote allowlists to fetch and allow

Other shared settings live in `ansible/group_vars/all/main.yml`:

- **Upstream resolvers** — `unbound_forward_addrs`
- **Local DNS / LAN hosts** — `lan_hosts`, `unbound_local_records`

Edit, re-run the playbook (or `./setup.sh`), done. The pihole role reconciles
lists into Pi-hole through its **REST API** (`pihole-sync-lists.py`): it adds
what's missing, removes what it previously added but is no longer listed, and
rebuilds gravity only when adlists actually change. It's declarative and
idempotent — a no-op run makes no changes. A remote allowlist that fails to
download is never treated as "removed", so a network blip can't wipe entries.

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
# Change the stored password:
nix-shell --run 'cd ansible && ansible-vault edit group_vars/all/vault.yml'

# Rotate the passphrase itself:
nix-shell --run 'cd ansible && ansible-vault rekey group_vars/all/vault.yml'
```

⚠️ Back up the **passphrase** (password manager) — lose it and the encrypted
file is unrecoverable.

## Backups

The `backup` role exports a Pi-hole **Teleporter** bundle (all config: adlists,
allow/deny, DHCP, settings) via the API and stores it weekly in a **restic**
repository on `jcu-nas2` over SFTP — encrypted, deduplicated, incremental. A
`pihole-backup.timer` runs it Sunday 04:30; retention keeps 8 weekly snapshots.

It's **off by default** (`backup_enabled: false`) so the playbook stays green
until the NAS is set up. To enable:

1. **Give the Pi SSH access to the NAS** — the Pi's root user must be able to
   `ssh <nas_user>@jcu-nas2` non-interactively (install a key).
2. **Add the restic repo password to the vault:**
   ```bash
   nix-shell --run 'cd ansible && ansible-vault edit group_vars/all/vault.yml'
   # add:  vault_restic_password: "a-strong-passphrase"
   ```
3. **Fill in the NAS details** in `group_vars/all/main.yml`: `backup_nas_user`,
   `backup_nas_path`, and set `backup_enabled: true`.
4. **Run the playbook.** It installs restic, `restic init`s the repo if needed,
   and enables the weekly timer.

Restore (on a fresh Pi, after `./setup.sh`): pull the latest snapshot with
`restic restore latest --target /tmp/restore`, then import the `.zip` via the
Pi-hole admin UI (Settings → Teleporter) or the API. A dead SD card becomes a
flash → `./setup.sh` → import recovery.

Run a backup on demand: `sudo systemctl start pihole-backup.service`.
