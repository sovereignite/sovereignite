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
              cfssl
              codex
              chromium
              google-chrome
              curl
              dasel
              dosfstools
              gettext
              go
              go-containerregistry
              protobuf
              protoc-gen-go
              protoc-gen-go-grpc
              gptfdisk
              jq
              ko
              kubectl
              kubernetes-helm
              kustomize
              libxml2
              nodejs
              opencode
              openssl
              opentofu
              shellcheck
              tpm2-pkcs11
              tpm2-tools

              yamllint

              # Required by the Kustomize developer agent.
              kpt
              gotools
              golangci-lint
              starlark
              bazel
              bazel-buildtools
              kubeconform
              conftest
              gnumake
              just
              go-task
              git

              # Optional language servers and additional validation tools.
              gopls
              starpls
              helm-ls
              yaml-language-server
              chart-testing
              kube-linter
              kustomize-lint

              # Optional container runtime for container-backed KRM functions. Choose one.
              podman

              
            ];
          };
          
        }
    );
}
