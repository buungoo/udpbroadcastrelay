{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.udpbroadcastrelay.dialIpv6;
in {
  options.services.udpbroadcastrelay.dialIpv6 = {
    enable = lib.mkEnableOption "the IPv6-client to IPv4-server DIAL gateway";
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix {};
      description = "udpbroadcastrelay package with --dial-ipv6 support.";
    };
    clientInterface = lib.mkOption {
      type = lib.types.str;
      description = "IPv6 client-side interface; only on-link clients are accepted.";
    };
    serverInterface = lib.mkOption {
      type = lib.types.str;
      description = "IPv4 device-side interface used for DIAL discovery and HTTP connections.";
    };
    listenAddress = lib.mkOption {
      type = lib.types.str;
      description = "Stable, non-link-local IPv6 address on clientInterface for the HTTP proxy.";
    };
    httpPort = lib.mkOption {
      type = lib.types.port;
      default = 1901;
    };
    replyPort = lib.mkOption {
      type = lib.types.port;
      default = 1901;
      description = "Fixed IPv4 UDP port for replies to the gateway's DIAL searches.";
    };
    clatDiscovery = lib.mkEnableOption ''
      experimental link-layer DIAL discovery from CLAT address 192.0.0.2.
      No IPv4 address, DHCP, ARP responder, or IPv4 HTTP listener is added on LAN.
      Requires CAP_NET_RAW only during startup; HTTP still uses IPv6
    '';
    debug = lib.mkEnableOption "DIAL discovery diagnostics without payloads or pairing parameters";
    forwardOrigins = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "Explicit public app origins allowed to be forwarded to TVs; never client/local addresses. Each origin must be a nonempty visible value under 2048 bytes; at most 16 are accepted.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.udpbroadcastrelay-dial-ipv6 = {
      description = "IPv6 to IPv4 DIAL discovery and application gateway";
      wantedBy = ["multi-user.target"];
      wants = ["network-online.target"];
      after = ["network-online.target"];
      serviceConfig = {
        ExecStart = lib.escapeShellArgs ([
          (lib.getExe cfg.package)
          "--dial-ipv6"
          "--client-dev" cfg.clientInterface
          "--server-dev" cfg.serverInterface
          "--listen-address" cfg.listenAddress
          "--http-port" (toString cfg.httpPort)
          "--reply-port" (toString cfg.replyPort)
        ] ++ lib.concatMap (origin: ["--forward-origin" origin]) cfg.forwardOrigins
          ++ lib.optional cfg.clatDiscovery "--clat-discovery"
          ++ lib.optional cfg.debug "-d");
        DynamicUser = true;
        Restart = "on-failure";
        RestartSec = "5s";
        NoNewPrivileges = true;
        CapabilityBoundingSet = if cfg.clatDiscovery then ["CAP_NET_RAW"] else "";
        AmbientCapabilities = lib.optional cfg.clatDiscovery "CAP_NET_RAW";
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictAddressFamilies = ["AF_INET" "AF_INET6" "AF_NETLINK"]
          ++ lib.optional cfg.clatDiscovery "AF_PACKET";
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        LimitNOFILE = 256;
      };
    };
  };
}
