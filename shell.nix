{
  pkgs ?
    import <nixpkgs> {
      config = {};
      overlays = [];
    },
}:
pkgs.mkShell {
  packages = with pkgs; [man-pages man-pages-posix];
}
