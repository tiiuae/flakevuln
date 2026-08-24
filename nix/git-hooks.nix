{ inputs, ... }:
{
  imports = with inputs; [
    git-hooks-nix.flakeModule
  ];
  perSystem =
    { pkgs, ... }:
    let
      pythonDeps = import ./python-deps.nix pkgs.python3.pkgs;
      # Python env used by pyright so it can resolve the project's imports.
      pyrightPythonEnv = pkgs.python3.withPackages (_: pythonDeps);
      pyrightWrapper = pkgs.writeShellScriptBin "pyright-flakevuln" ''
        exec ${pkgs.lib.getExe pkgs.pyright} --pythonpath ${pyrightPythonEnv}/bin/python "$@"
      '';
    in
    {
      pre-commit = {
        settings.hooks = {
          gitlint.enable = true;
          typos = {
            enable = true;
            excludes = [
              "^LICENSES/.*"
              "\\.csv$"
            ];
          };
          end-of-file-fixer = {
            enable = true;
            excludes = [
              "^LICENSES/.*"
              "\\.csv$"
            ];
          };
          trim-trailing-whitespace = {
            enable = true;
            excludes = [
              "^LICENSES/.*"
              "\\.csv$"
            ];
          };
          yamlfmt = {
            enable = true;
            args = [
              "-formatter"
              "retain_line_breaks_single=true"
            ];
            settings.lint-only = false;
          };
          actionlint.enable = true;
          action-validator = {
            enable = true;
            files = "^action\\.ya?ml$";
          };
          deadnix.enable = true;
          nixfmt.enable = true;
          pyright = {
            enable = true;
            pass_filenames = false;
            settings.binPath = "${pyrightWrapper}/bin/pyright-flakevuln";
          };
          ruff.enable = true;
          ruff-format.enable = true;
          reuse.enable = true;
          shellcheck.enable = true;
          statix = {
            enable = true;
            args = [ "fix" ];
          };
        };
      };
    };
}
