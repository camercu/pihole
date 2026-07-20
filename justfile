# Task runner. Run inside the nix env (direnv, or `nix-shell --run 'just <recipe>'`).

# List available recipes.
default:
    @just --list

# Lint the Python helper scripts (ruff) and the Ansible playbooks/roles.
lint:
    ruff check .
    cd ansible && ansible-lint
