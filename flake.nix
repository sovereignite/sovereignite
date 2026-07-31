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
      in
        {
          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              btrfs-progs
              bzip2
              butane
              cfssl
              codex
              curl
              dasel
              dosfstools
              gettext
              go
              go-containerregistry
              gptfdisk
              jq
              kubectl
              kubernetes-helm
              kustomize
              libxml2
              libvirt
              opencode
              openssl
              opentofu
              qemu
              shellcheck
              skopeo
              step-cli
              tpm2-pkcs11
              tpm2-tools
              yq-go
              yamllint
            ];
          };
          
        }
    );
}
