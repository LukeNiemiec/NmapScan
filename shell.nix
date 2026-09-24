{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
	buildInputs = [
		pkgs.
	];

	shellHook = ''
	# alias run=""

	clear
	 '';
}
