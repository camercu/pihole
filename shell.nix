# Pin nixpkgs so the toolchain is identical on every host and in CI — no
# reliance on an ambient <nixpkgs> channel (which CI doesn't have). Bump the rev
# + sha256 deliberately. This rev matches the channel this repo was built on.
{ pkgs ? import
    (fetchTarball {
      url = "https://github.com/NixOS/nixpkgs/archive/cc598dfd09b0a543d574a238d4b3473bb1c6d587.tar.gz";
      sha256 = "1i68i9mbiyg5a46mg97kkxz3p46b7s4zmhzz1cv8gryl83mspbn6";
    })
    { }
}:

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
    restic # backup round-trip in the integration tests (matches the backup role)
    (python3.withPackages (ps: [ ps.pytest ])) # unit tests for the helper scripts
  ];
}
