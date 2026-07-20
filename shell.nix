{ pkgs ? import <nixpkgs> { } }:

# Dev/control-node toolchain for this repo. Run all repo tooling through this
# env (`nix-shell --run '<cmd>'` or direnv) so ansible versions don't drift
# between host and CI.
pkgs.mkShell {
  packages = with pkgs; [
    ansible # ansible-core + community collections (control node)
    ansible-lint # static analysis for playbooks/roles
    sshpass # only needed for first-boot password SSH before keys are installed
    ruff # lint + format the helper scripts
    pre-commit # run the safety-net hooks (ruff, ansible-lint, pytest)
    just # task runner (see justfile)
    (python3.withPackages (ps: [ ps.pytest ])) # unit tests for the helper scripts
  ];
}
