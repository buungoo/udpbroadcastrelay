UDP Broadcast Relay for Linux / FreeBSD / pfSense / OPNsense
============================================================
( For Opensense a plugin is already available )

This program listens for packets on a specified UDP broadcast port. When
a packet is received, it sends that packet to all specified interfaces
but the one it came from as though it originated from the original
sender.

The primary purpose of this is to allow devices or game servers on separated
local networks (Ethernet, WLAN, VLAN) that use udp broadcasts to find each
other to do so.

INSTALL
-------

Building requires a C compiler, `pkg-config`, and libevent 2.1 development files.
The fork can also be built with `nix build` or developed with `nix develop`.

    make
    cp udpbroadcastrelay /some/where

USAGE
-----

```
./udpbroadcastrelay \
    --id id \
    --port <udp-port> \
    --dev eth0 --dev eth1
    [--dev ethx...] \
    [--blockid id...] \
    [--blockcidr network-prefix/size] \
    [--allowcidr network-prefix/size] \
    [--msearch action[,search-term]] \   
    [--multicast 224.0.0.251] \
    [-s <spoof_source_ip>]
    [-t|--ttl-id] [-d] [-f]
    [-h|--help]
```

- udpbroadcastrelay must be run as root to be able to create a raw
  socket (necessary) to send packets as though they originated from the
  original sender.
- `id` must be unique number between instances with range 1 - 63. This is
  used to set the DSCP of outgoing packets to determine if a packet is an
  echo and should be discarded.
- `blockid` can be used to drop packets received from other instances of
  udpbroadcastrelay using the specified ID value.
- `--blockcidr` can be used to block packets from a range of IP source
  addresses, given in CIDR notation. This option can be specified multiple
  times to block more than one range. Where multiple overlapping CIDRs are
  specified with the `--blockcidr` and `--allowcidr` options the most
  specific match (longest prefix) will take effect.
- `--allowcidr` can be used to only allow packets from a range of IP source
  addresses, given in CIDR notation. This option can be specified multiple
  times to allow more than one range. Once this option is specified the
  default behaviour for packets which does not any CIDRs changes from
  Allow to Block.
- `udp-port` Destination udp port to listen to. Range 1 - 65535.
  Example values for common services are given below.
- `-dev <ethx>` specifies the name of an interface to receive and
  transmit packets on. This option needs to be specified at least twice
  for 2 separate interfaces otherwise this tool won't actually do
  anything!
- The tool can listen for and relay packets using multicast groups
  with
  `--multicast <group address>`.
- The source address for all packets can be modified with `-s <ip>`. This
  is unusual.
- A special source ip of `-s 1.1.1.1` can be used to change the source ip 
  of the relayed packets to match the ip address of the relay server's 
  destination interface. Additionally, the source UDP port for the server's
  destination interface is set to the same destination port found in the 
  original packet. 
  `-s 1.1.1.2` does the same but leaves the UDP ports unchanged. These 
  values are notably required to cater for the Chromecast system.
- Special SSDP processing can be turned on using the `--msearch` option.
  By default SSDP M-SEARCH packets are treated the same as any other
  packet. The `action` parameter changes this default:
  - `block`:  drop the M-SEARCH packet.
  - `fwd`:    forward the M-SEARCH packet like a regular packet (and the
  `-s` into account).
  - `proxy`:  create a local proxy for M-SEARCH requests. Set the M-SEARCH 
    UDP source to the IP of the relay's destination network interface 
    before relaying. Addtionally, the UDP source port is updated to a port 
    that is tracked by the proxy for relaying responses back to the 
    correct requesting host.
    Received responses are sent back to original requester with no 
    processing. i.e. the requester will receive an SSDP reponse with a 
    LOCATION referencing a host on the other network.
  - `dial`:   perform full DIAL protocol processing on M-SEARCH request.
  Create proxies for M-SEARCH (same as `proxy`), Locator and REST services. 
  Use this for Youtube app on Smart TVs. 
  
  When a `search-term` is also specified the given action will only apply
  to M-SEARCH packets containing this specific search term. `--msearch`
  can be specified multiple times to add more search terms. The value of `-s`
  affects normal and M-SEARCH packets with the forward action.
  
  The old `-s 1.1.1.3` option should be replaced with `--msearch dial`.
  
- The original version of this tool marked the TTL of outgoing relayed
  packets to detect echos and preserved DSCP. This original behavior can
  be restored by setting the [-t|--ttl-id] parameter.
- `-d` will enable debugging output. Specify `-d` twice for extra debugging info
- `-f` will fork the application to the background and create a pid file
  at /var/run/udpbroadcastrelay_ID.pid
- `-h|--help` Display a detailed help dialog.

EXAMPLE
-------

#### mDNS / Multicast DNS (Chromecast Discovery + Bonjour + More)
`./udpbroadcastrelay --id 1 --port 5353 --dev eth0 --dev eth1 --multicast 224.0.0.251 -s 1.1.1.1`

(Chromecast requires broadcasts to originate from an address on its subnet)

#### mDNS example which allows messages from hosts on 192.168.1.0/24 and 192.168.20.0/24 subnets but blocks host 192.168.20.20
`./udpbroadcastrelay --id 1 --port 5353 --dev eth0 --dev eth1 --multicast 224.0.0.251 -s 1.1.1.1 --allowcidr 192.168.1.0/24 --allowcidr 192.168.20.0/24 --blockcidr 192.168.20.20/32`

This will prevent relaying broadcast/multicast packets from host 192.168.20.20. It will not stop any unicast traffic from this host.
 
#### SSDP (Roku Discovery, DLNA Media, Sonos, UPnP + More)
`./udpbroadcastrelay --id 1 --port 1900 --dev eth0 --dev eth1 --multicast 239.255.255.250`

#### Youtube Application on Smart TV
`./udpbroadcastrelay --id 1 --dev eth0 --dev eth1 --port 1900 --multicast 239.255.255.250 -s 1.1.1.2 --msearch dial`

#### IPv6 phones / IPv4 Smart TV: DIAL gateway (Linux)

```
./udpbroadcastrelay --dial-ipv6 \
    --client-dev br-lan --server-dev br-tv \
    --listen-address 2001:db8:1::1 \
    --http-port 1901 --reply-port 1901
```

Use an IPv6 address actually assigned to the client interface. This opt-in mode
accepts DIAL M-SEARCH requests over IPv6 (multicast `ff02::c:1900`, or unicast to
the gateway), searches for IPv4 DIAL servers on the device interface, and returns
IPv6-reachable discovery URLs. `LOCATION`, `Application-URL`, and HTTP redirect
URLs are proxied through one fixed IPv6 HTTP port. Device descriptions and
application request/response bodies are passed through, not interpreted.

By default, the phone app **must itself support IPv6 SSDP/DIAL discovery and IPv6
HTTP**. Some iOS YouTube versions instead send IPv4 DIAL searches from the CLAT
address `192.0.0.2`, even on IPv6-only Wi-Fi. Linux's experimental
`--clat-discovery` option accepts precisely that discovery traffic at layer 2:

```
./udpbroadcastrelay --dial-ipv6 --clat-discovery \
    --client-dev br-lan --server-dev br-tv \
    --listen-address 2001:db8:1::1 --http-port 1901 --reply-port 1901
```

It does **not** assign an IPv4 address to LAN, run DHCP, answer ARP, bridge the
segments, or proxy IPv4 HTTP. A validated search triggers the same canonical
device-side search as IPv6 discovery. Responses go directly to the requesting
client's MAC/IP/UDP port, using the relay's existing device-side IPv4 address
as the source. The returned `LOCATION` is still the IPv6 HTTP proxy. Clients
sharing `192.0.0.2` are tracked separately by MAC and port.

This is deliberately not general SSDP: only unfragmented Ethernet/IPv4 UDP
packets from `192.0.0.2` to `239.255.255.250:1900`, with an exact DIAL search and
bounded `MX`, are accepted. Other IPv4 sources, IP options, fragments, invalid
checksums, and VLAN-tagged frames are rejected. Use the realized client bridge
interface, not a trunk. Requests and replies must fit a 1500-byte IP packet.

**Real-device acceptance still needs testing.** The app must accept a unicast
IPv4 discovery reply whose `LOCATION` uses IPv6, then perform IPv6 HTTP. The shim
cannot make an IPv4-only HTTP client work, and an emitted reply is not proof that
iOS delivered it to YouTube. Check both discovery and the subsequent HTTP
request. This is not an mDNS gateway, a Google Cast emulator, or a replacement for
AirPlay discovery.

Without `--clat-discovery`, the gateway does not need root or raw sockets with
the default ports. CLAT discovery requires `CAP_NET_RAW` at startup to open one
client-interface-bound packet socket, attach a restrictive kernel filter, and
lock that filter. All effective, permitted, inheritable, and ambient capabilities
are then dropped; no `CAP_NET_ADMIN` is needed. Raw-socket setup or capability
drop failure is fatal. Run it under a service manager; it stays in the foreground
and handles SIGTERM/SIGINT.
`--dial-ipv6 --help` lists the separate mode's options. The legacy IPv4 relay's
flags and CIDR filters do not apply to this mode.

Isolation is retained by terminating requests on the gateway rather than
bridging the networks:

- Only on-link clients from `--client-dev` may use discovery and the HTTP proxy.
- Only DIAL servers answering a recent client search on the IPv4 device subnet
  can register endpoints. Numeric HTTP addresses must match that responding
  device. Client-supplied arbitrary destinations and DNS targets are rejected.
- Description URLs are read-only; application requests must remain under an
  advertised application endpoint. Routes expire after an hour.
- Searches sent to TVs are rebuilt without phone headers. HTTP requests use a
  generic User-Agent and do not forward cookies, authorization, Origin, or
  client-IP headers by default. `--forward-origin ORIGIN` is an opt-in,
  repeatable allowlist (maximum 16 values): only an exact matching caller
  `Origin` is forwarded to the TV. Configure only explicitly approved public
  app origins, for example `https://sender.example`; never configure a phone,
  LAN, or other local address. Caller-supplied origins not on the list are
  stripped. This does not forward cookies or authorization. Response cookies
  are not forwarded. Pairing data in DIAL payloads still reaches the TV, as
  required by casting.
- Searches, registered endpoints, concurrent requests, body sizes, and request
  times are bounded. Payloads and pairing parameters are not logged.

This protects the DIAL path, not other discovery daemons. If TVs must not discover
LAN hosts, **do not also enable a bidirectional mDNS/SSDP reflector** between
these segments. Publish only selected TV records onto LAN, with an explicit
publication interface, and retain the device-to-LAN firewall deny policy.

Permit only these **input** flows on the router (no new device-to-LAN forwarding):

1. Client interface: IPv6 UDP destination 1900 for `ff02::c` or the gateway address.
2. Client interface: IPv6 TCP to the gateway's listen address and HTTP port.
3. Device interface: IPv4 UDP from the device subnet to the gateway's device-side
   IPv4 address and fixed reply port. Do **not** require source port 1900: some
   DIAL servers reply from dynamically allocated UDP ports. The gateway still
   requires a pending search, a valid DIAL response, and matching device/URL
   addresses. Multicast-search replies may not be recognized as established by
   connection tracking, hence this explicit input rule.

The CLAT socket operates at layer 2 before the IP input firewall and has its own
locked filter; do not add an IPv4 LAN address or an IPv4 firewall accept rule for
it. It accepts discovery only and sends no LAN frames into the device segment.

The exported NixOS module provides `services.udpbroadcastrelay.dialIpv6` with
`clientInterface`, `serverInterface`, `listenAddress`, `httpPort`, `replyPort`,
`clatDiscovery` (default false), `debug` (default false), and `forwardOrigins`
(a list of at most 16 explicitly approved public app origins, default `[]`).
`forwardOrigins` follows the same exact-match privacy policy as
`--forward-origin`; do not put client or local addresses in it. It creates a dynamic
user service, granting only the CLAT startup capability when opted in; firewall
policy remains with the site/router configuration. `debug` logs discovery stages,
not packet contents or pairing data.

`make check` tests the frame codec without privileges. See `tests/README.md` for
an end-to-end test in a private user/network namespace, without changing the
router's live interfaces or requiring host root.

#### Youtube Application on Smart TV along with DLNA media playback
`./udpbroadcastrelay --id 1 --dev eth0 --dev eth1 --port 1900 --multicast 239.255.255.250 -s 1.1.1.2 --msearch proxy,urn:schemas-upnp-org:device:MediaServer:1 --msearch dial`

#### Lifx Bulb Discovery
`./udpbroadcastrelay --id 1 --port 56700 --dev eth0 --dev eth1`

#### Broadlink IR Emitter Discovery
`./udpbroadcastrelay --id 1 --port 80 --dev eth0 --dev eth1`

#### Warcraft 3 Server Discovery
`./udpbroadcastrelay --id 1 --port 6112 --dev eth0 --dev eth1`

#### Windows Network Neighborhood Discovery
 NetBIOS Name Service (137), SMB Browser (138) and SSDP (1900).
 Windows Network Discovery across networks relies on relaying
 these three protocols all at once.
 To requires that three separate instances of udpbroadcastrelay
 run simultaneously so in this example we execute the command
 with the "-f" parameter in order to run the tool in the
 background.
`./udpbroadcastrelay --id 1 --port 137 --dev eth0 --dev eth1 -f`
`./udpbroadcastrelay --id 2 --port 138 --dev eth0 --dev eth1 -f`
`./udpbroadcastrelay --id 3 --port 1900 --dev eth0 --dev eth1 --multicast 239.255.255.250 -f`

#### Syncthing Discovery
`./udpbroadcastrelay --id 1 --port 21027 --dev eth0 --dev eth1`

#### Raknet Discovery (Minecraft)
`./udpbroadcastrelay --id 1 --port 19132 --dev eth0 --dev eth1`

Note about firewall rules
---

If you are running udpbroadcastrelay on a router, it can be an easy
way to relay broadcasts between VLANs. However, beware that these broadcasts
will not establish a RELATED firewall relationship between the source and
destination addresses.

This means if you have strict firewall rules, the recipient may not be able
to respond to the broadcaster. For instance, the SSDP protocol involves
sending a broadcast packet to port 1900 to discover devices on the network.
The devices then respond to the broadcast with a unicast packet back to the
original sender. You will need to make sure that your firewall rules allow
these response packets to make it back to the original sender.


Recent changes
--------------

- Added --blockcidr and --allowcidr options
- Print interface names instead of numbers in packet information messages
- Removed the `-s 1.1.1.3` option and replaced it with a more general `--msearch`
  option, which allows finer control (see USAGE section)
- Updated the expiry time for M-SEARCH, Locator and REST proxies.
- Fixed build information not being printed when `-d` is specififed
- Introduced a second level of debug info, activated by specifying `-d` twice

Please note: Maintenance of this project is on a 'when I have a moment' basis, and that may be several months.
