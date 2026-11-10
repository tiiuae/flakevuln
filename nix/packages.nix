{ self, ... }:
{
  perSystem =
    {
      pkgs,
      inputs',
      lib,
      config,
      self',
      ...
    }:
    let
      pp = pkgs.python3.pkgs;
      pythonDeps = import ./python-deps.nix {
        inherit pp;
        sbomnix = inputs'.sbomnix.packages.default;
      };
      baseVersion = lib.removeSuffix "\n" (builtins.readFile ../VERSION);
      # Append git state so local builds are distinguishable from release
      # artifacts. shortRev is set on a clean tree; dirtyShortRev (Nix >= 2.14)
      # is set when the working tree has uncommitted changes.
      gitSuffix =
        if self ? shortRev then
          "+g${self.shortRev}"
        else if self ? dirtyShortRev then
          "+g${self.dirtyShortRev}"
        else
          "";
      version = "${baseVersion}${gitSuffix}";
      # Thin wrapper that runs the module entry point via the ambient python3.
      # PYTHONPATH (set in shellHook) resolves to the local src/, so edits are
      # picked up without reinstalling.
      mkDevEntry =
        name: module:
        pkgs.writeShellScriptBin name ''
          exec python3 -c "import sys; sys.argv[0]='${name}'; from ${module} import main; main()" "$@"
        '';
      # Tools the scanner shells out to at runtime.
      runtime_inputs = [
        pkgs.git
        pkgs.nix
        inputs'.sbomnix.packages.default
      ];
      check_inputs = with pp; [
        pytest
        pytestCheckHook
      ];
      build_system = with pp; [ setuptools ];
      build_inputs = pythonDeps;
    in
    {
      packages = {
        default = config.packages.flakevuln;
        flakevuln = pp.buildPythonPackage {
          pname = "flakevuln";
          inherit version;
          pyproject = true;
          src = lib.cleanSource ../.;
          postPatch = ''
            printf '%s' "${version}" > VERSION
          '';
          build-system = build_system;
          nativeCheckInputs = check_inputs;
          dependencies = build_inputs;
          pythonImportsCheck = [ "flakevuln" ];
          makeWrapperArgs = [
            "--prefix PATH : ${lib.makeBinPath runtime_inputs}"
          ];
        };
      };

      # Force a build of all packages during a `nix flake check`.
      checks = lib.mapAttrs' (n: lib.nameValuePair "package-${n}") self'.packages;

      devShells.default = pkgs.mkShell {
        name = "flakevuln-devshell";
        packages = [
          pkgs.pyright # for running pyright manually in the devshell
          pkgs.ruff # for running ruff manually in the devshell
        ]
        ++ runtime_inputs
        ++ check_inputs
        ++ build_system
        ++ build_inputs
        ++ [ (mkDevEntry "flakevuln" "flakevuln.main") ];
        shellHook = ''
          ${config.pre-commit.installationScript}
          echo 1>&2 "Welcome to the flakevuln development shell!"
          # Resolve the in-tree sources so entrypoints pick up local edits.
          export PYTHONPATH="$PYTHONPATH:$(pwd)/src"
          # https://github.com/NixOS/nix/issues/1009:
          export TMPDIR="/tmp"
        '';
      };
    };
}
