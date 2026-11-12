#include "dial-clat.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const unsigned char local_mac[6] = {2, 0, 0, 0, 0, 1};
static const unsigned char phone_mac[6] = {2, 0, 0, 0, 0, 2};
static const char request[] = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
    "MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n";

static unsigned int get16(const unsigned char *p)
{
    return ((unsigned int)p[0] << 8) | p[1];
}

static void set16(unsigned char *p, unsigned int value)
{
    p[0] = value >> 8;
    p[1] = value;
}

static unsigned int checksum(const unsigned char *p, size_t length)
{
    unsigned int sum = 0;
    for (size_t i = 0; i < length; i += 2)
        sum += ((unsigned int)p[i] << 8) | (i + 1 < length ? p[i + 1] : 0);
    while (sum > 0xffff)
        sum = (sum & 0xffff) + (sum >> 16);
    return (~sum) & 0xffff;
}

static unsigned int udp_checksum(const unsigned char *frame)
{
    unsigned char data[DIAL_CLAT_FRAME_SIZE] = {0};
    unsigned int length = get16(frame + 38);
    memcpy(data, frame + 26, 8);
    data[9] = 17;
    set16(data + 10, length);
    memcpy(data + 12, frame + 34, length);
    return checksum(data, length + 12);
}

static void fix_checksums(unsigned char *frame)
{
    set16(frame + 24, 0);
    set16(frame + 24, checksum(frame + 14, 20));
    set16(frame + 40, 0);
    unsigned int result = udp_checksum(frame);
    set16(frame + 40, result ? result : 0xffff);
}

static size_t make_request(unsigned char *frame)
{
    const unsigned char multicast[6] = {1, 0, 0x5e, 0x7f, 0xff, 0xfa};
    size_t size = 42 + strlen(request);
    memset(frame, 0, DIAL_CLAT_FRAME_SIZE);
    memcpy(frame, multicast, 6);
    memcpy(frame + 6, phone_mac, 6);
    set16(frame + 12, 0x0800);
    frame[14] = 0x45;
    set16(frame + 16, size - 14);
    frame[22] = 2;
    frame[23] = 17;
    memcpy(frame + 26, "\xc0\x00\x00\x02\xef\xff\xff\xfa", 8);
    set16(frame + 34, 61203);
    set16(frame + 36, 1900);
    set16(frame + 38, size - 34);
    memcpy(frame + 42, request, strlen(request));
    fix_checksums(frame);
    return size;
}

static size_t parse(const unsigned char *frame, size_t length, size_t capacity)
{
    char payload[DIAL_CLAT_FRAME_SIZE];
    struct dial_clat_peer peer;
    return dial_clat_parse(frame, length, local_mac, &peer, payload, capacity);
}

int main(void)
{
    unsigned char good[DIAL_CLAT_FRAME_SIZE], bad[DIAL_CLAT_FRAME_SIZE];
    size_t size = make_request(good);
    char payload[DIAL_CLAT_FRAME_SIZE];
    struct dial_clat_peer peer;
    assert(dial_clat_parse(good, size, local_mac, &peer, payload, sizeof(payload)) == strlen(request));
    assert(!strcmp(payload, request));
    assert(!memcmp(peer.mac, phone_mac, 6));
    assert(peer.port == htons(61203));
    assert(peer.address.s_addr == inet_addr("192.0.0.2"));
    for (size_t i = 0; i < size; i++)
        assert(!parse(good, i, sizeof(payload)));
    assert(!parse(good, size, strlen(request)));
    assert(!parse(good, DIAL_CLAT_FRAME_SIZE + 1, sizeof(payload)));

    const unsigned int offsets[] = {0, 6, 12, 14, 16, 20, 22, 23, 24, 26, 30, 34, 36, 38, 40, 42};
    for (size_t i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        memcpy(bad, good, sizeof(bad));
        bad[offsets[i]] ^= 1;
        /* Changing TTL 2 to 3 still invalidates its checksum. */
        assert(!parse(bad, size, sizeof(payload)));
    }
    memcpy(bad, good, sizeof(bad));
    set16(bad + 40, 0); /* UDP checksum is optional in IPv4. */
    assert(parse(bad, size, sizeof(payload)) == strlen(request));
    memcpy(bad + 6, local_mac, 6);
    assert(!parse(bad, size, sizeof(payload)));
    memset(bad + 6, 0, 6);
    assert(!parse(bad, size, sizeof(payload)));

    memcpy(bad, good, sizeof(bad));
    bad[29] = 3; /* Another IPv4 address is rejected even with correct checksums. */
    fix_checksums(bad);
    assert(!parse(bad, size, sizeof(payload)));
    memcpy(bad, good, sizeof(bad));
    bad[20] = 0x20; /* More fragments. */
    fix_checksums(bad);
    assert(!parse(bad, size, sizeof(payload)));
    memcpy(bad, good, sizeof(bad));
    bad[21] = 1; /* Non-first fragment. */
    fix_checksums(bad);
    assert(!parse(bad, size, sizeof(payload)));
    memcpy(bad, good, sizeof(bad));
    bad[14] = 0x46; /* IP options. */
    assert(!parse(bad, size, sizeof(payload)));

    struct in_addr source = {.s_addr = inet_addr("192.0.2.1")};
    const char reply[] = "HTTP/1.1 200 OK\r\nLOCATION: http://[2001:db8:1::1]:1901/dial/1/\r\n\r\n";
    size_t encoded = dial_clat_encode(bad, sizeof(bad), local_mac, source, &peer, reply, strlen(reply));
    assert(encoded == 42 + strlen(reply));
    assert(!memcmp(bad, phone_mac, 6) && !memcmp(bad + 6, local_mac, 6));
    assert(!memcmp(bad + 26, &source, 4) && !memcmp(bad + 30, &peer.address, 4));
    assert(get16(bad + 34) == 1900 && get16(bad + 36) == 61203);
    assert(get16(bad + 16) == encoded - 14 && get16(bad + 38) == encoded - 34);
    assert(bad[22] == 1 && !checksum(bad + 14, 20) && !udp_checksum(bad));
    assert(!memcmp(bad + 42, reply, strlen(reply)));
    assert(!dial_clat_encode(bad, 42, local_mac, source, &peer, reply, strlen(reply)));
    assert(!dial_clat_encode(bad, sizeof(bad), local_mac, source, &peer, payload, sizeof(payload)));
    peer.mac[0] |= 1;
    assert(!dial_clat_encode(bad, sizeof(bad), local_mac, source, &peer, reply, strlen(reply)));

    /* Exercise length/checksum parsing with deterministic mutations under ASan. */
    unsigned int random = 1;
    for (unsigned int i = 0; i < 10000; i++) {
        memcpy(bad, good, sizeof(bad));
        random = random * 1664525u + 1013904223u;
        bad[random % sizeof(bad)] ^= (random >> 16) | 1;
        (void)parse(bad, (random >> 8) % (sizeof(bad) + 1), sizeof(payload));
    }
    puts("CLAT frame codec: all tests passed");
    return 0;
}
