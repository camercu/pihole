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

## Prerequisites

- [Nix](https://nixos.org/download) on your control machine (Mac/Linux). All
  tooling runs through `nix-shell` so ansible versions don't drift.
- A Pi reachable over SSH. Set `ansible_host` / `ansible_user` in
  `ansible/inventory.yml`.
- Your SSH public key in `authorized_ssh_keys` (`group_vars/all.yml`) if you
  want key auth managed for you.

With [direnv](https://direnv.net/): `direnv allow` drops you into the env
automatically. Otherwise prefix commands with `nix-shell --run '…'`.

## Usage

```bash
# Full rebuild from a fresh Pi:
nix-shell --run 'cd ansible && ansible-playbook site.yml'

# Preview without changing anything:
nix-shell --run 'cd ansible && ansible-playbook site.yml --check --diff'

# One role only (tags: common, unbound, pihole, maintenance):
nix-shell --run 'cd ansible && ansible-playbook site.yml --tags pihole'

# Static checks:
nix-shell --run 'cd ansible && ansible-playbook --syntax-check site.yml'
nix-shell --run 'cd ansible && ansible-lint'
```

First run may prompt for the SSH password (`-k`) and sudo (`-K`) until your key
is installed and passwordless sudo is set up.

## Changing configuration

Everything lives in `ansible/group_vars/all.yml`:

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

The Pi-hole admin / API password is stored **encrypted** in
`group_vars/all/vault.yml` as `vault_pihole_web_password`; `main.yml` references
it via `pihole_web_password`. The encrypted file is safe to commit — the
passphrase that decrypts it never is.

**One-time setup:**

```bash
# 1. Save your vault passphrase to the gitignored key file (or skip this and
#    use --ask-vault-pass to type it each run).
printf '%s' 'YOUR_VAULT_PASSPHRASE' > ansible/.vault-pass && chmod 600 ansible/.vault-pass

# 2. Create the encrypted vars file and add the Pi-hole password.
nix-shell --run 'cd ansible && ansible-vault create group_vars/all/vault.yml'
#    In the editor, add one line:
#      vault_pihole_web_password: "YOUR_PIHOLE_ADMIN_PASSWORD"

# 3. Commit it — it's ciphertext.
git add ansible/group_vars/all/vault.yml && git commit -m "chore: add vaulted pihole password"
```

**Daily use:** `direnv` auto-exports `ANSIBLE_VAULT_PASSWORD_FILE` when
`ansible/.vault-pass` exists, so `ansible-playbook site.yml` just works. Without
direnv, add `--ask-vault-pass` (prompt) or `--vault-password-file .vault-pass`.

- Edit later: `ansible-vault edit group_vars/all/vault.yml`
- Rotate the passphrase: `ansible-vault rekey group_vars/all/vault.yml`
- ⚠️ Back up the **passphrase** itself (password manager) — lose it and the
  encrypted file is unrecoverable. The key file `ansible/.vault-pass` is
  gitignored; don't commit it.

## Backups (not yet implemented)

Recommended next role: a daily `restic`/`rsync` of `/etc/pihole` and
`/etc/dnsmasq.d` (or the whole config) to `jcu-nas2` (192.168.0.11). That turns
a dead SD card into a ~10-minute recovery: flash → run playbook → restore.
