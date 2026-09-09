# Task runner. Run inside the nix env (direnv, or `nix-shell --run 'just <recipe>'`).

# List available recipes.
default:
    @just --list

# Lint the Python helper scripts (ruff) and the Ansible playbooks/roles.
lint:
    ruff check .
    cd ansible && ansible-lint

# Quick pre-commit gate: ruff lint + fast unit tests (`lint` adds ansible-lint).
check:
    ruff check .
    just test

# Auto-fix what ruff can (import order, simple lints), then report the rest.
fix:
    ruff check --fix .

# Fast unit tests (end-to-end container tests skip unless PIHOLE_IT=1).
test:
    pytest -q

# Needs docker or podman on PATH; pulls the pinned pihole image on first run.
[doc("Full test suite incl. end-to-end tests against a real Pi-hole container")]
test-full:
    PIHOLE_IT=1 pytest -q

[doc("Apply this repo's configuration to the Pi")]
deploy:
    cd ansible && ansible-playbook site.yml

# Additions and deletions both, so the UI can be where you work. Writes into
# ansible/roles/pihole/files/; review with `git diff` before committing. Never
# touches the Pi. Declines to prune a file the box holds nothing of, and says
# so; pass --force-prune to the script if everything really was deleted.
[doc("Capture changes made by hand in the admin UI into the config files")]
mirror:
    cd ansible && ansible-playbook mirror.yml

# Run after committing the mirror diff AND deploying it: adopt refuses while the
# Pi is reconciling from config files other than the ones you just reviewed.
[doc("Hand entries captured by `just mirror` over to the reconciler")]
adopt:
    cd ansible && ansible-playbook adopt.yml
