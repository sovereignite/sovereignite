{
  inputs = {
    flake-utils = {
      url = "github:numtide/flake-utils";
    };

    nixpkgs = {
      url = "github:NixOS/nixpkgs/nixos-unstable";
    }; 
  };

  outputs =
    {
      self,
      flake-utils,
      nixpkgs,
    }@inputs:
    
    flake-utils.lib.eachDefaultSystem (
      system:

      let
        pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };

        specialArgs = inputs // {
          inherit inputs pkgs;
        };
      in
        {
          inherit specialArgs;

          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              btrfs-progs
              codex
              dasel
              dosfstools
              go
              gptfdisk
              jq
              libxml2
              opencode
            ];
          };
          
        }
    );
}
