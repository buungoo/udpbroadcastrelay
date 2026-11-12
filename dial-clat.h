/* Link-local IPv4 discovery for CLAT clients. Same GPL-2.0-or-later as main.c. */
#ifndef DIAL_CLAT_H
#define DIAL_CLAT_H

#include <netinet/in.h>
#include <stddef.h>
#include <sys/types.h>

#define DIAL_CLAT_FRAME_SIZE 1514

struct dial_clat_peer {
    struct in_addr address;
    unsigned short port; /* Network byte order. */
    unsigned char mac[6];
};

struct dial_clat {
    int fd;
    unsigned int ifindex;
    unsigned char mac[6];
    struct in_addr source;
};

/* The codec is separate so malformed frames can be tested without privileges. */
size_t dial_clat_parse(const unsigned char *frame, size_t length,
    const unsigned char local_mac[6], struct dial_clat_peer *peer,
    char *payload, size_t capacity);
size_t dial_clat_encode(unsigned char *frame, size_t capacity,
    const unsigned char local_mac[6], struct in_addr source,
    const struct dial_clat_peer *peer, const char *payload, size_t length);

int dial_clat_open(struct dial_clat *clat, unsigned int ifindex, struct in_addr source);
ssize_t dial_clat_receive(struct dial_clat *clat, struct dial_clat_peer *peer,
    char *payload, size_t capacity);
int dial_clat_reply(struct dial_clat *clat, const struct dial_clat_peer *peer,
    const char *payload, size_t length);
int dial_clat_drop_capabilities(void);

#endif
