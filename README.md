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

Shared, non-secret settings live in `ansible/group_vars/all/main.yml`:

- **Blocklists** — `pihole_adlists`
- **Remote allowlists** — `pihole_allowlist_urls`
- **Local allow entries** (exact + regex) — `ansible/roles/pihole/files/allow.list`
- **Upstream resolvers** — `unbound_forward_addrs`
- **Local DNS / LAN hosts** — `lan_hosts`, `unbound_local_records`

Edit, re-run the playbook, done. List changes trigger a gravity rebuild
automatically.

## ⚠️ Verify on first real apply

I could not run this against your actual Pi, and Pi-hole **v6** (what a fresh
install gives you in 2026) changed its config store and CLI. The following are
built against the version-stable `gravity.db` schema but should be confirmed on
the box during the first run:

- **List application** (`roles/pihole/files/apply-lists.sh`) — inserts adlists
  and allow entries via `sqlite3` then runs `pihole -g`. Check the entries land
  in the admin UI.
- **Upstream enforcement** (`Point Pi-hole upstream at local unbound (v6)`) —
  uses `pihole-FTL --config dns.upstreams`. Confirm the key/CLI on your version;
  `failed_when: false` keeps it non-fatal meanwhile.
- **Web password** — uses `pihole setpassword`.

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

## Backups (not yet implemented)

Recommended next role: a daily `restic`/`rsync` of `/etc/pihole` and
`/etc/dnsmasq.d` (or the whole config) to `jcu-nas2` (192.168.0.11). That turns
a dead SD card into a ~10-minute recovery: flash → run playbook → restore.
