# Network integration tests

Run the IPv4 CLAT discovery integration test in an isolated user/network
namespace (no host sudo or live-router changes):

```sh
unshare --user --map-root-user --net python3 tests/test-clat-network.py ./udpbroadcastrelay
```

The test needs `iproute2`, Python 3, and permission for raw packet sockets in
the new namespace. It creates only private veth pairs, verifies that the
client-side links have no IPv4 addresses, injects a forged IPv4 SSDP M-SEARCH
at Ethernet level, and captures TV-side traffic to ensure malformed packets
and non-DIAL searches are rejected. It verifies canonical DIAL forwarding,
same-IPv4/same-port clients distinguished by MAC, direct-MAC replies, and
rewritten IPv6 `LOCATION`. It then fetches the device description and follows
its rewritten `Application-URL` over IPv6 to a separate mock application
endpoint. It also checks an application POST body and content type, preserves a
201 response with a rewritten `Location`, and follows that location with a GET.
The mock application requires an authorized `Origin` for launch: only exact
configured web/package origins pass, while local and lookalike origins,
authorization, cookies, and client-address headers remain hidden. DIAL
`API-Version` response metadata is preserved.
Effective, permitted, inheritable, and ambient capabilities must all
be zero after startup (the bounding set is intentionally not checked).
