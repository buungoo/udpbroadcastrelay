#!/usr/bin/env python3
"""Isolated end-to-end test for the IPv4-over-IPv6 DIAL CLAT shim.

Run: unshare --user --map-root-user --net python3 tests/test-clat-network.py ./udpbroadcastrelay
Requires iproute2 and raw-socket permission in that private namespace.
"""
import http.server
import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time

LAN_GW = '2001:db8:1::1'
LAN_PHONE = '2001:db8:1::2'
TV = '192.0.2.72'
GW4 = '192.0.2.1'
CLAT_PORT = 54321
ST = b'urn:dial-multiscreen-org:service:dial:1'
PHONE_MAC = bytes.fromhex('020000000002')
PHONE2_MAC = bytes.fromhex('020000000003')
GW_MAC = bytes.fromhex('020000000001')
APP_ORIGIN = 'https://sender.example'
PACKAGE_ORIGIN = 'package:org.example.sender'
HTTP_REQUESTS = []
HTTP_POSTS = []


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def command(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def ip_bytes(address):
    return socket.inet_aton(address)


def make_ipv4_udp(payload, src='192.0.0.2', dst='239.255.255.250', sport=CLAT_PORT,
                  dport=1900, ident=42, flags=0, options=b'', corrupt_ip=False,
                  corrupt_udp=False):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    pseudo = ip_bytes(src) + ip_bytes(dst) + struct.pack('!BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp)) + udp[8:]
    if corrupt_udp:
        udp = udp[:6] + bytes([udp[6] ^ 1]) + udp[7:]
    ihl = 20 + len(options)
    header = struct.pack('!BBHHHBBH4s4s', (4 << 4) | (ihl // 4), 0,
                          ihl + len(udp), ident, flags, 64, 17, 0,
                          ip_bytes(src), ip_bytes(dst)) + options
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    if corrupt_ip:
        header = header[:10] + bytes([header[10] ^ 1]) + header[11:]
    return header + udp


def ethernet(ip_packet, source=PHONE_MAC):
    return bytes.fromhex('01005e7ffffa') + source + b'\x08\x00' + ip_packet


def parse_ipv4(frame):
    if len(frame) < 34 or frame[12:14] != b'\x08\x00':
        return None
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    if ip[0] >> 4 != 4 or ihl < 20 or len(ip) < ihl + 8:
        return None
    total = struct.unpack('!H', ip[2:4])[0]
    if total < ihl + 8 or total > len(ip) or checksum(ip[:ihl]) != 0:
        return None
    if ip[9] != 17 or struct.unpack('!H', ip[6:8])[0] & 0x3fff:
        return None
    udp = ip[ihl:total]
    if struct.unpack('!H', udp[4:6])[0] != len(udp):
        return None
    return (frame[:6], frame[6:12], ip[12:16], ip[16:20],
            *struct.unpack('!HH', udp[:4]), udp[8:])


def msearch(st=ST, extra=b'', man=b'"ssdp:discover"', mx=b'1'):
    return (b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: ' + man +
            b'\r\nMX: ' + mx + b'\r\nST: ' + st + b'\r\n' + extra + b'\r\n')


class TvHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        HTTP_REQUESTS.append((self.client_address[0], dict(self.headers)))
        if self.path == '/dd.xml':
            body = b'<root><device><friendlyName>mock TV</friendlyName></device></root>'
            self.send_response(200)
            self.send_header('Content-Type', 'text/xml')
            self.send_header('Application-URL', 'http://192.0.2.72:8000/apps/')
        elif self.path.startswith('/apps/'):
            body = b'APP_PROXY_OK:' + self.path.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
        else:
            body = b'not found'
            self.send_response(404)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        HTTP_POSTS.append((self.client_address[0], self.path, dict(self.headers), body))
        if self.path != '/apps/launch':
            self.send_error(404)
            return
        # Some DIAL applications require an authorized Origin for launch.
        if self.headers.get('Origin') != APP_ORIGIN:
            self.send_error(403)
            return
        response = b'launch accepted'
        self.send_response(201)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Location', 'http://192.0.2.72:8000/apps/run')
        self.send_header('API-Version', 'v1.00')
        self.send_header('Content-Length', str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *_args):
        pass


def http_get(path, method='GET', body=b'', content_type=None,
             origin='http://[2001:db8:1::2]'):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.bind((LAN_PHONE, 0))
    sock.connect((LAN_GW, 1901))
    request = ('%s %s HTTP/1.1\r\nHost: [%s]:1901\r\nConnection: close\r\n'
               'User-Agent: synthetic-client\r\n'
               'X-Forwarded-For: 2001:db8:1::2\r\nCookie: test=value\r\n'
               'Authorization: Bearer synthetic-value\r\n' %
                (method, path, LAN_GW))
    if origin is not None:
        request += 'Origin: %s\r\n' % origin
    if content_type:
        request += 'Content-Type: %s\r\n' % content_type
    if body:
        request += 'Content-Length: %d\r\n' % len(body)
    sock.sendall((request + '\r\n').encode() + body)
    data = bytearray()
    while True:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data.extend(chunk)
    sock.close()
    head, body = bytes(data).split(b'\r\n\r\n', 1)
    return head, body


def main():
    check(os.geteuid() == 0, 'must run inside --map-root-user user namespace')
    with open('/proc/self/uid_map', encoding='ascii') as f:
        mapping = f.read().split()
    check(len(mapping) == 3 and mapping[0] == '0' and mapping[1] != '0' and mapping[2] == '1',
          'refusing network setup outside a single-ID user namespace')
    check(len(sys.argv) == 2, 'usage: test-clat-network.py GATEWAY-BINARY')
    binary = os.path.abspath(sys.argv[1])
    check(os.path.isfile(binary), 'gateway binary does not exist: ' + binary)

    command('ip', 'link', 'set', 'lo', 'up')
    command('ip', 'link', 'add', 'lan0', 'type', 'veth', 'peer', 'name', 'phone0')
    command('ip', 'link', 'add', 'jail0', 'type', 'veth', 'peer', 'name', 'tv0')
    for dev in ('lan0', 'phone0', 'jail0', 'tv0'):
        command('ip', 'link', 'set', dev, 'up')
    command('ip', '-6', 'addr', 'add', LAN_GW + '/64', 'dev', 'lan0', 'nodad')
    command('ip', '-6', 'addr', 'add', LAN_PHONE + '/64', 'dev', 'phone0', 'nodad')
    command('ip', 'addr', 'add', GW4 + '/24', 'dev', 'jail0')
    command('ip', 'addr', 'add', TV + '/24', 'dev', 'tv0')
    command('ip', 'link', 'set', 'lan0', 'address', GW_MAC.hex(':'))
    command('ip', 'link', 'set', 'phone0', 'address', PHONE_MAC.hex(':'))
    for dev in ('lan0', 'phone0'):
        check(not subprocess.check_output(['ip', '-4', '-o', 'addr', 'show', 'dev', dev]).strip(),
              dev + ' unexpectedly has IPv4')

    tv_ssdp_raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    tv_ssdp_raw.bind(('tv0', 0))
    tv_ssdp_raw.setblocking(False)
    phone_raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    phone_raw.bind(('phone0', 0))
    tv_http = http.server.ThreadingHTTPServer((TV, 80), TvHandler)
    app_http = http.server.ThreadingHTTPServer((TV, 8000), TvHandler)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (tv_http, app_http)]
    for thread in threads:
        thread.start()
    proc = subprocess.Popen([binary, '--dial-ipv6', '--client-dev', 'lan0', '--server-dev',
                             'jail0', '--listen-address', LAN_GW, '--clat-discovery',
                             '--forward-origin', APP_ORIGIN,
                             '--forward-origin', PACKAGE_ORIGIN, '-d'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        time.sleep(.4)
        if proc.poll() is not None:
            raise AssertionError('gateway failed to start: ' + proc.stderr.read().decode())

        def inject(packet, mac=PHONE_MAC):
            phone_raw.send(ethernet(packet, mac))

        def tv_search(timeout):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                ready, _, _ = select.select([tv_ssdp_raw], [], [],
                                            max(0, deadline - time.monotonic()))
                if not ready:
                    break
                parsed = parse_ipv4(tv_ssdp_raw.recv(65535))
                if parsed and parsed[5] == 1900 and parsed[6].startswith(b'M-SEARCH '):
                    return parsed
            return None

        def rejected(packet, label):
            inject(packet)
            check(tv_search(.12) is None, '%s unexpectedly caused a TV search' % label)

        # Each malformed/forbidden packet is individually checked not to trigger TV discovery.
        valid = msearch()
        rejected(make_ipv4_udp(valid, src='192.0.0.3'), 'wrong IPv4 source')
        rejected(make_ipv4_udp(valid, dst='192.0.0.1'), 'non-multicast destination')
        rejected(make_ipv4_udp(valid, flags=0x2000), 'fragment')
        rejected(make_ipv4_udp(valid, options=b'\x01\x01\x01\x01'), 'IPv4 options')
        rejected(make_ipv4_udp(valid, corrupt_ip=True), 'bad IPv4 checksum')
        rejected(make_ipv4_udp(valid, corrupt_udp=True), 'bad UDP checksum')
        rejected(make_ipv4_udp(msearch(st=b'ssdp:all')), 'non-DIAL ST')
        rejected(make_ipv4_udp(msearch(man=b'"ssdp:alive"')), 'wrong MAN')
        rejected(make_ipv4_udp(msearch(mx=b'0')), 'invalid MX')
        rejected(make_ipv4_udp(valid, dport=1901), 'wrong destination port')
        # Two client MACs share exactly the CLAT IPv4 and UDP source port.
        # Both outstanding searches must get the response, each via its own L2 route.
        inject(make_ipv4_udp(msearch(extra=b'X-Test-Client: must-not-forward\r\n')), PHONE_MAC)
        upstream = tv_search(2)
        check(upstream is not None, 'valid CLAT search did not reach the TV interface')
        first_search = upstream[6]
        check(b'ST: ' + ST + b'\r\n' in first_search and b'X-Test-Client' not in first_search,
              'upstream request was not canonical DIAL or leaked phone headers')
        check(upstream[2] == ip_bytes(GW4), 'upstream request did not originate at relay IPv4 address')
        inject(make_ipv4_udp(msearch()), PHONE2_MAC)
        # Search rate limiting may suppress the second upstream M-SEARCH; it must
        # still register its independent return route for the pending response.
        time.sleep(.1)
        reply = (b'HTTP/1.1 200 OK\r\nST: ' + ST + b'\r\nUSN: uuid:test::' + ST +
                 b'\r\nLOCATION: http://' + TV.encode() + b'/dd.xml\r\n\r\n')
        tv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # A DIAL response may originate from an ephemeral port, not UDP 1900.
        tv.bind((TV, 0))
        check(tv.getsockname()[1] != 1900, 'test must exercise an ephemeral response source')
        tv.sendto(reply, (GW4, 1901))
        phone_raw.settimeout(3)
        frames = {}
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and len(frames) < 2:
            packet = parse_ipv4(phone_raw.recv(65535))
            if packet and packet[3] == ip_bytes('192.0.0.2') and packet[4:6] == (1900, CLAT_PORT):
                frames[packet[0]] = packet
        check(set(frames) == {PHONE_MAC, PHONE2_MAC},
               'reply did not fan out to both MACs sharing the CLAT address and port')
        for mac, response in frames.items():
            check(response[2] == ip_bytes(GW4) and response[3] == ip_bytes('192.0.0.2'),
                  'wrong CLAT reply IPv4 source/destination')
            check(b'LOCATION: http://[' + LAN_GW.encode() + b']:1901/dial/' in response[6],
                  'LOCATION was not rewritten to IPv6 proxy')
        location = re.search(rb'LOCATION: http://\[[^]]+\]:1901(/[^\r\n]+)', frames[PHONE_MAC][6], re.I)
        check(location, 'could not read proxied description URL')
        description_path = location.group(1).decode()

        # Exercise the IPv6 HTTP listener end-to-end and then follow the rewritten
        # Application-URL to the separate mock TV application endpoint.
        desc_headers, desc_body = http_get(description_path)
        check(b'200' in desc_headers.split(b'\r\n', 1)[0] and b'mock TV' in desc_body,
              'IPv6 proxied description GET failed')
        app = re.search(rb'(?im)^Application-URL:\s*http://\[[^]]+\]:1901(/[^\r\n]+)', desc_headers)
        check(app, 'description Application-URL was not rewritten to IPv6 proxy')
        app_path = app.group(1).decode()
        app_path = app_path.rstrip('/') + '/status'
        app_headers, app_body = http_get(app_path)
        check(b'200' in app_headers.split(b'\r\n', 1)[0] and b'APP_PROXY_OK:/apps/status' in app_body,
               'IPv6 application proxy GET did not reach the TV app endpoint')
        http_get(app_path, origin=APP_ORIGIN)
        http_get(app_path, origin=APP_ORIGIN + '.unlisted.example')

        launch_body = b'generic launch request'
        forbidden_headers, _ = http_get(
            app.group(1).decode().rstrip('/') + '/launch', method='POST',
            body=launch_body, content_type='text/plain; charset=utf-8')
        check(b'403' in forbidden_headers.split(b'\r\n', 1)[0],
              'unlisted local Origin was forwarded or backend rejection was hidden')
        launch_headers, launch_response = http_get(
            app.group(1).decode().rstrip('/') + '/launch', method='POST',
            body=launch_body, content_type='text/plain; charset=utf-8', origin=APP_ORIGIN)
        check(b'201' in launch_headers.split(b'\r\n', 1)[0] and
               launch_response == b'launch accepted',
               'IPv6 application POST did not preserve the 201 response')
        check(re.search(rb'(?im)^API-Version:\s*v1\.00\s*$', launch_headers),
              'DIAL API-Version response metadata was dropped')
        run = re.search(rb'(?im)^Location:\s*http://\[[^]]+\]:1901(/[^\r\n]+)', launch_headers)
        check(run, 'application POST Location was not rewritten to IPv6 proxy')
        run_headers, run_body = http_get(run.group(1).decode(), origin=PACKAGE_ORIGIN)
        check(b'200' in run_headers.split(b'\r\n', 1)[0] and
              b'APP_PROXY_OK:/apps/run' in run_body,
              'GET following the rewritten launch Location failed')
        check(len(HTTP_POSTS) == 2, 'unexpected number of proxied application POST requests')
        for (source, post_path, post_headers, post_body), expected_origin in zip(
                HTTP_POSTS, (None, APP_ORIGIN)):
            post_headers = {key.lower(): value for key, value in post_headers.items()}
            check(source == GW4 and post_path == '/apps/launch',
                  'application POST did not reach the expected TV endpoint')
            check(post_body == launch_body and
                  post_headers.get('content-type') == 'text/plain; charset=utf-8',
                  'application POST body or Content-Type was not preserved')
            check(post_headers.get('origin') == expected_origin,
                  'POST Origin did not respect the forwarding allowlist')
            check(not {'x-forwarded-for', 'cookie', 'authorization'} & post_headers.keys(),
                  'client-identifying HTTP headers leaked in launch POST')
        expected_origins = (None, None, APP_ORIGIN, None, PACKAGE_ORIGIN)
        check(len(HTTP_REQUESTS) == len(expected_origins), 'unexpected number of proxied GET requests')
        for (source, headers), expected_origin in zip(HTTP_REQUESTS, expected_origins):
            headers = {key.lower(): value for key, value in headers.items()}
            check(source == GW4, 'TV saw a client source address instead of the relay')
            check(headers.get('user-agent') == 'udpbroadcastrelay-dial-ipv6/1',
                  'client User-Agent leaked to TV')
            check(headers.get('origin') == expected_origin,
                  'GET Origin did not respect the forwarding allowlist')
            check(not {'x-forwarded-for', 'cookie', 'authorization'} & headers.keys(),
                   'client-identifying HTTP headers leaked to TV')

        # Confirm no capabilities remain except the capability bounding set, which
        # is intentionally not required to be zero.
        status = open('/proc/%d/status' % proc.pid, encoding='ascii').read()
        for line in status.splitlines():
            if line.startswith(('CapEff:', 'CapPrm:', 'CapInh:', 'CapAmb:')):
                check(int(line.split()[1], 16) == 0, 'gateway retained capabilities: ' + line)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        for server in (tv_http, app_http):
            server.shutdown()
            server.server_close()
        for sock in (phone_raw, tv_ssdp_raw):
            sock.close()
    print('CLAT network integration test passed')


if __name__ == '__main__':
    main()
