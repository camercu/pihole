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

# Full suite incl. end-to-end tests against a real Pi-hole container.
# Needs docker or podman on PATH; pulls the pinned pihole image on first run.
test-full:
    PIHOLE_IT=1 pytest -q
