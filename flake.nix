{
  description = "JavaCard Gradle Template";
  inputs = {
    gradle2nix.url = "github:tadfisher/gradle2nix/v2";
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, ... }@inputs: let
      forEachSystem = inputs.flake-utils.lib.eachSystem inputs.flake-utils.lib.allSystems;
  in forEachSystem (system: let
    pkgs = import inputs.nixpkgs rec {
      inherit system;
      # config.allowUnfree = true;
    };
    defaultPackage = inputs.gradle2nix.builders.${system}.buildGradlePackage {
      pname = "applet";
      version = "0.1";
      src = ./.;
      lockFile = ./gradle.lock;
      gradleFlags = [ "buildjavacard" ];
    };
    # gradle = pkgs.gradle;
    jdk = pkgs.jdk8_headless;

    installPhase = ''
      mkdir -p $out
      touch $out/bin
    '';

    JAVA_HOME = "${jdk}";

  in {
    packages.default = defaultPackage;
    devShells = with pkgs; {
      default = mkShell {
        name = "gradle2nix";
        packages = [
          nodejs
          inputs.gradle2nix.packages.${system}.gradle2nix
        ];
        inputsFrom = [ gradle jdk ];

        GRADLE_HOME = "${gradle}";
        JAVA_HOME = "${jdk}";

      };
    };
  });
}
