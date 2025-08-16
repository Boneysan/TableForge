{ pkgs }: {
  deps = [
    pkgs.nodejs-20_x
    pkgs.nodePackages.npm
    pkgs.nodePackages.typescript
    pkgs.nodePackages.typescript-language-server
    pkgs.postgresql
    pkgs.git
  ];
  
  env = {
    NODE_ENV = "development";
    PATH = "${pkgs.nodejs-20_x}/bin:${pkgs.nodePackages.npm}/bin:${pkgs.nodePackages.typescript}/bin:$PATH";
  };
}
