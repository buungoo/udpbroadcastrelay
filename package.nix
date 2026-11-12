{
  lib,
  stdenv,
  pkg-config,
  libevent,
}:
stdenv.mkDerivation {
  pname = "udpbroadcastrelay";
  version = "1.3.0-dial-ipv6";
  src = ./.;

  nativeBuildInputs = [pkg-config];
  buildInputs = [libevent];

  doCheck = true;

  installPhase = ''
    runHook preInstall
    install -Dm755 udpbroadcastrelay "$out/bin/udpbroadcastrelay"
    runHook postInstall
  '';

  meta = {
    description = "UDP relay with an IPv6-client to IPv4-server DIAL gateway";
    homepage = "https://github.com/buungoo/udpbroadcastrelay";
    license = lib.licenses.gpl2Plus;
    platforms = lib.platforms.linux;
    mainProgram = "udpbroadcastrelay";
  };
}
