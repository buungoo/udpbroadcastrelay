/* Narrow IPv4 SSDP shim, not an IPv4 LAN or an IPv4 forwarding path. */
#define _GNU_SOURCE
#include "dial-clat.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

#define ETHER_SIZE 14
#define IP_SIZE 20
#define UDP_SIZE 8
#define PAYLOAD_OFFSET (ETHER_SIZE + IP_SIZE + UDP_SIZE)

static const unsigned char ssdp_mac[6] = {0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa};

static unsigned int word(const unsigned char *p)
{
    return ((unsigned int)p[0] << 8) | p[1];
}

static void put_word(unsigned char *p, unsigned int value)
{
    p[0] = (unsigned char)(value >> 8);
    p[1] = (unsigned char)value;
}

static uint32_t checksum_add(const unsigned char *p, size_t length, uint32_t sum)
{
    for (; length >= 2; p += 2, length -= 2)
        sum += word(p);
    if (length)
        sum += (unsigned int)p[0] << 8;
    return sum;
}

static unsigned int checksum_finish(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (~sum) & 0xffff;
}

static int unicast_mac(const unsigned char mac[6])
{
    static const unsigned char zero[6];
    return !(mac[0] & 1) && memcmp(mac, zero, sizeof(zero));
}

size_t dial_clat_parse(const unsigned char *frame, size_t length,
    const unsigned char local_mac[6], struct dial_clat_peer *peer,
    char *payload, size_t capacity)
{
    if (length < PAYLOAD_OFFSET || length > DIAL_CLAT_FRAME_SIZE ||
        memcmp(frame, ssdp_mac, sizeof(ssdp_mac)) || !unicast_mac(frame + 6) ||
        !memcmp(frame + 6, local_mac, 6) || word(frame + 12) != 0x0800)
        return 0;
    const unsigned char *ip = frame + ETHER_SIZE;
    /* No IP options, fragments, VLAN encapsulation, or general IPv4 clients. */
    if (ip[0] != 0x45 || !ip[8] || ip[9] != 17 || (word(ip + 6) & 0xbfff) ||
        memcmp(ip + 12, "\xc0\x00\x00\x02", 4) ||
        memcmp(ip + 16, "\xef\xff\xff\xfa", 4) ||
        checksum_finish(checksum_add(ip, IP_SIZE, 0)))
        return 0;
    size_t ip_length = word(ip + 2);
    const unsigned char *udp = ip + IP_SIZE;
    size_t udp_length = word(udp + 4);
    if (ip_length < IP_SIZE + UDP_SIZE || ip_length > length - ETHER_SIZE ||
        udp_length != ip_length - IP_SIZE || !word(udp) || word(udp + 2) != 1900)
        return 0;
    size_t payload_length = udp_length - UDP_SIZE;
    if (!payload_length || payload_length >= capacity)
        return 0;
    if (word(udp + 6) && checksum_finish(checksum_add(udp, udp_length,
            checksum_add(ip + 12, 8, 17 + (uint32_t)udp_length))))
        return 0;
    memcpy(&peer->address, ip + 12, 4);
    memcpy(&peer->port, udp, 2);
    memcpy(peer->mac, frame + 6, 6);
    memcpy(payload, udp + UDP_SIZE, payload_length);
    payload[payload_length] = 0;
    return payload_length;
}

size_t dial_clat_encode(unsigned char *frame, size_t capacity,
    const unsigned char local_mac[6], struct in_addr source,
    const struct dial_clat_peer *peer, const char *payload, size_t length)
{
    if (!length || length > DIAL_CLAT_FRAME_SIZE - PAYLOAD_OFFSET ||
        capacity < PAYLOAD_OFFSET + length || !unicast_mac(local_mac) ||
        !unicast_mac(peer->mac) || !peer->port ||
        memcmp(&peer->address, "\xc0\x00\x00\x02", 4))
        return 0;
    memset(frame, 0, PAYLOAD_OFFSET);
    memcpy(frame, peer->mac, 6);
    memcpy(frame + 6, local_mac, 6);
    put_word(frame + 12, 0x0800);
    unsigned char *ip = frame + ETHER_SIZE;
    ip[0] = 0x45;
    put_word(ip + 2, IP_SIZE + UDP_SIZE + length);
    put_word(ip + 6, 0x4000); /* Do not fragment; every reply fits Ethernet's MTU. */
    ip[8] = 1;
    ip[9] = 17;
    memcpy(ip + 12, &source, 4);
    memcpy(ip + 16, &peer->address, 4);
    put_word(ip + 10, checksum_finish(checksum_add(ip, IP_SIZE, 0)));
    unsigned char *udp = ip + IP_SIZE;
    put_word(udp, 1900);
    memcpy(udp + 2, &peer->port, 2);
    put_word(udp + 4, UDP_SIZE + length);
    memcpy(udp + UDP_SIZE, payload, length);
    unsigned int checksum = checksum_finish(checksum_add(udp, UDP_SIZE + length,
        checksum_add(ip + 12, 8, 17 + UDP_SIZE + (uint32_t)length)));
    put_word(udp + 6, checksum ? checksum : 0xffff);
    return PAYLOAD_OFFSET + length;
}

#ifdef __linux__
int dial_clat_open(struct dial_clat *clat, unsigned int ifindex, struct in_addr source)
{
    /* Protocol zero prevents reception until the filter is installed and locked. */
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return 0;
    struct sock_filter instructions[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 15),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 14),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x45, 0, 13),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 17, 0, 11),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 20),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0xbfff, 9, 0),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 26),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xc0000002, 0, 7),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 30),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0xeffffffa, 0, 5),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 36),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1900, 0, 3),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, SKF_AD_OFF + SKF_AD_PKTTYPE),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PACKET_OUTGOING, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, DIAL_CLAT_FRAME_SIZE),
        BPF_STMT(BPF_RET | BPF_K, 0),
    };
    struct sock_fprog filter = {
        .len = sizeof(instructions) / sizeof(instructions[0]), .filter = instructions
    };
    int yes = 1;
    struct sockaddr_ll address = {
        .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_IP), .sll_ifindex = (int)ifindex
    };
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) < 0 ||
        setsockopt(fd, SOL_SOCKET, SO_LOCK_FILTER, &yes, sizeof(yes)) < 0 ||
        bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0)
        goto failed;
    socklen_t size = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &size) < 0)
        goto failed;
    if (address.sll_hatype != ARPHRD_ETHER || address.sll_halen != 6 ||
        !unicast_mac(address.sll_addr)) {
        errno = EINVAL;
        goto failed;
    }
    clat->fd = fd;
    clat->ifindex = ifindex;
    clat->source = source; /* Existing relay address on the TV side, never a TV's address. */
    memcpy(clat->mac, address.sll_addr, 6);
    return 1;
failed: {
        int error = errno;
        close(fd);
        errno = error;
        return 0;
    }
}

ssize_t dial_clat_receive(struct dial_clat *clat, struct dial_clat_peer *peer,
    char *payload, size_t capacity)
{
    unsigned char frame[DIAL_CLAT_FRAME_SIZE];
    struct sockaddr_ll address;
    socklen_t size = sizeof(address);
    ssize_t length = recvfrom(clat->fd, frame, sizeof(frame), MSG_TRUNC,
        (struct sockaddr *)&address, &size);
    if (length <= 0)
        return length;
    if ((size_t)length > sizeof(frame) || size < sizeof(address) ||
        address.sll_ifindex != (int)clat->ifindex || address.sll_pkttype != PACKET_MULTICAST)
        return 0;
    return (ssize_t)dial_clat_parse(frame, (size_t)length, clat->mac, peer, payload, capacity);
}

int dial_clat_reply(struct dial_clat *clat, const struct dial_clat_peer *peer,
    const char *payload, size_t length)
{
    unsigned char frame[DIAL_CLAT_FRAME_SIZE];
    size_t size = dial_clat_encode(frame, sizeof(frame), clat->mac, clat->source,
        peer, payload, length);
    if (!size)
        return 0;
    struct sockaddr_ll address = {
        .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex = (int)clat->ifindex, .sll_halen = 6
    };
    memcpy(address.sll_addr, peer->mac, 6);
    return sendto(clat->fd, frame, size, 0, (struct sockaddr *)&address, sizeof(address)) == (ssize_t)size;
}

int dial_clat_drop_capabilities(void)
{
    struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3 };
    struct __user_cap_data_struct data[2] = {{0}};
    /* The already-open, interface-bound, filter-locked socket is all we retain. */
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
        syscall(SYS_capset, &header, data) == 0;
}
#else
int dial_clat_open(struct dial_clat *clat, unsigned int ifindex, struct in_addr source)
{
    (void)clat; (void)ifindex; (void)source;
    errno = ENOTSUP;
    return 0;
}

ssize_t dial_clat_receive(struct dial_clat *clat, struct dial_clat_peer *peer,
    char *payload, size_t capacity)
{
    (void)clat; (void)peer; (void)payload; (void)capacity;
    errno = ENOTSUP;
    return -1;
}

int dial_clat_reply(struct dial_clat *clat, const struct dial_clat_peer *peer,
    const char *payload, size_t length)
{
    (void)clat; (void)peer; (void)payload; (void)length;
    return 0;
}

int dial_clat_drop_capabilities(void)
{
    return 0;
}
#endif
