/* IPv6-client / IPv4-server DIAL gateway. Same GPL-2.0-or-later as main.c. */
#define _GNU_SOURCE
#include "dial-ipv6.h"
#include "dial-clat.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/util.h>

#define DIAL_ST "urn:dial-multiscreen-org:service:dial:1"
#define SSDP_PORT 1900
#define MAX_PACKET 8192
#define MAX_URI 2048
#define MAX_ROUTES 128
#define MAX_SEARCHES 64
#define MAX_REQUESTS 32
#define MAX_FORWARD_ORIGINS 16
#define ROUTE_LIFETIME 3600
#define SEARCH_LIFETIME 4

struct route {
    uint64_t id;
    struct in_addr address;
    unsigned short port;
    int application;
    char path[MAX_URI];
    time_t expires;
};

struct search {
    struct sockaddr_in6 peer;
    struct dial_clat_peer clat_peer;
    int clat;
    time_t expires;
};

struct gateway;
struct request {
    struct gateway *gateway;
    struct evhttp_request *front;
    struct evhttp_request *back;
    struct evhttp_connection *connection;
    struct route route;
    enum evhttp_cmd_type method;
    struct request *next;
};

struct gateway {
    const char *client_dev;
    const char *server_dev;
    unsigned int client_index;
    struct in6_addr address6;
    struct in_addr address4;
    struct in_addr mask4;
    char text6[INET6_ADDRSTRLEN];
    char text4[INET_ADDRSTRLEN];
    unsigned short http_port;
    unsigned short reply_port;
    int socket6;
    int socket4;
    struct dial_clat clat;
    int clat_discovery;
    int verbose;
    char forward_origins[MAX_FORWARD_ORIGINS][MAX_URI];
    size_t forward_origin_count;
    time_t last_search;
    uint64_t next_id;
    struct route routes[MAX_ROUTES];
    struct search searches[MAX_SEARCHES];
    struct request *requests;
    unsigned int request_count;
    struct event_base *base;
    struct evhttp *http;
    struct event *read6;
    struct event *read4;
    struct event *read_clat;
    struct event *term;
    struct event *interrupt;
};

static void usage(const char *program)
{
    fprintf(stderr,
        "Usage: %s --dial-ipv6 --client-dev IFACE --server-dev IFACE\n"
        "       --listen-address IPV6 [--http-port 1901] [--reply-port 1901]\n"
        "       [--clat-discovery] [--forward-origin ORIGIN ...] [-d]\n"
        "\nProxy IPv6 DIAL M-SEARCH requests to IPv4 TVs. No raw sockets required.\n"
        "Optional --clat-discovery accepts IPv4 DIAL from 192.0.0.2 at layer 2\n"
        "without adding IPv4 to the client interface (Linux, CAP_NET_RAW at startup).\n"
        "All clients must support IPv6 HTTP. No mDNS or generic SSDP is relayed.\n",
        program);
}

static time_t now(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        abort();
    return ts.tv_sec;
}

static int port_number(const char *text, unsigned short *port)
{
    char *end;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || !*text || *end || value == 0 || value > 65535)
        return 0;
    *port = (unsigned short)value;
    return 1;
}

static int valid_origin(const char *origin)
{
    size_t length = strlen(origin);
    if (!length || length >= MAX_URI)
        return 0;
    for (const unsigned char *p = (const unsigned char *)origin; *p; p++)
        if (*p <= 32 || *p >= 127)
            return 0;
    return 1;
}

/* Also used on HTTP peers: clients must be on the selected interface's link. */
static int client_allowed(struct gateway *g, const struct sockaddr_in6 *peer)
{
    if (IN6_IS_ADDR_UNSPECIFIED(&peer->sin6_addr) ||
        IN6_IS_ADDR_MULTICAST(&peer->sin6_addr) ||
        IN6_IS_ADDR_V4MAPPED(&peer->sin6_addr))
        return 0;
    if (IN6_IS_ADDR_LINKLOCAL(&peer->sin6_addr))
        return peer->sin6_scope_id == g->client_index;

    struct ifaddrs *addresses;
    if (getifaddrs(&addresses) < 0)
        return 0;
    int allowed = 0;
    for (struct ifaddrs *a = addresses; a; a = a->ifa_next) {
        if (!a->ifa_addr || !a->ifa_netmask ||
            a->ifa_addr->sa_family != AF_INET6 ||
            strcmp(a->ifa_name, g->client_dev))
            continue;
        const unsigned char *local = ((struct sockaddr_in6 *)a->ifa_addr)->sin6_addr.s6_addr;
        const unsigned char *mask = ((struct sockaddr_in6 *)a->ifa_netmask)->sin6_addr.s6_addr;
        int matches = 1;
        for (size_t i = 0; i < 16; i++)
            if ((local[i] & mask[i]) != (peer->sin6_addr.s6_addr[i] & mask[i]))
                matches = 0;
        if (matches) {
            allowed = 1;
            break;
        }
    }
    freeifaddrs(addresses);
    return allowed;
}

static int interfaces(struct gateway *g)
{
    struct ifaddrs *addresses;
    int found6 = 0, found4 = 0;
    g->client_index = if_nametoindex(g->client_dev);
    if (!g->client_index || !if_nametoindex(g->server_dev) ||
        getifaddrs(&addresses) < 0)
        return 0;
    for (struct ifaddrs *a = addresses; a; a = a->ifa_next) {
        if (!a->ifa_addr || !(a->ifa_flags & IFF_UP))
            continue;
        if (a->ifa_addr->sa_family == AF_INET6 && !strcmp(a->ifa_name, g->client_dev)) {
            struct in6_addr address = ((struct sockaddr_in6 *)a->ifa_addr)->sin6_addr;
            if (!memcmp(&address, &g->address6, sizeof(address)))
                found6 = 1;
        }
        if (!found4 && a->ifa_netmask && a->ifa_addr->sa_family == AF_INET &&
            !strcmp(a->ifa_name, g->server_dev)) {
            g->address4 = ((struct sockaddr_in *)a->ifa_addr)->sin_addr;
            g->mask4 = ((struct sockaddr_in *)a->ifa_netmask)->sin_addr;
            found4 = 1;
        }
    }
    freeifaddrs(addresses);
    inet_ntop(AF_INET, &g->address4, g->text4, sizeof(g->text4));
    return found4 && found6;
}

/* Return exactly one header value. Folded/duplicate headers are not accepted. */
static int header(const char *packet, const char *name, char *value, size_t size)
{
    const char *line = strstr(packet, "\r\n");
    int found = 0;
    if (!line)
        return 0;
    line += 2;
    while (*line && strncmp(line, "\r\n", 2)) {
        const char *end = strstr(line, "\r\n");
        const char *colon = strchr(line, ':');
        if (!end || !colon || colon >= end || isspace((unsigned char)*line))
            return 0;
        if ((size_t)(colon - line) == strlen(name) && !strncasecmp(line, name, strlen(name))) {
            if (found++)
                return 0;
            const char *start = colon + 1;
            while (start < end && (*start == ' ' || *start == '\t'))
                start++;
            while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
                end--;
            if ((size_t)(end - start) >= size)
                return 0;
            for (const char *p = start; p < end; p++)
                if (((unsigned char)*p < 32 && *p != '\t') || *p == 127)
                    return 0;
            memcpy(value, start, (size_t)(end - start));
            value[end - start] = 0;
        }
        line = strstr(line, "\r\n") + 2;
    }
    return found == 1;
}

static int path_safe(const char *path)
{
    size_t length;
    char *decoded = evhttp_uridecode(path, 0, &length);
    if (!decoded)
        return 0;
    int safe = length == strlen(decoded) && decoded[0] == '/' &&
        !strstr(decoded, "//") && !strchr(decoded, '\\') && !strchr(decoded, '%');
    for (size_t i = 0; i < length; i++) {
        if ((unsigned char)decoded[i] < 32 || decoded[i] == 127)
            safe = 0;
        if (decoded[i] == '/' && decoded[i + 1] == '.' &&
            (decoded[i + 2] == '/' || decoded[i + 2] == 0 ||
             (decoded[i + 2] == '.' && (decoded[i + 3] == '/' || decoded[i + 3] == 0))))
            safe = 0;
    }
    free(decoded);
    return safe;
}

/* Register only numeric HTTP endpoints on the device that supplied discovery. */
static struct route *register_route(struct gateway *g, const char *url,
    struct in_addr device, int application)
{
    struct evhttp_uri *uri = evhttp_uri_parse(url);
    if (!uri)
        return NULL;
    const char *scheme = evhttp_uri_get_scheme(uri);
    const char *host = evhttp_uri_get_host(uri);
    const char *path = evhttp_uri_get_path(uri);
    const char *query = evhttp_uri_get_query(uri);
    struct in_addr address;
    int port = evhttp_uri_get_port(uri);
    if (port == -1)
        port = 80;
    if (!scheme || strcasecmp(scheme, "http") || !host ||
        inet_pton(AF_INET, host, &address) != 1 || address.s_addr != device.s_addr ||
        evhttp_uri_get_userinfo(uri) || evhttp_uri_get_fragment(uri) ||
        port < 1 || port > 65535 || (application && query)) {
        evhttp_uri_free(uri);
        return NULL;
    }
    if (!path || !*path)
        path = "/";
    char resource[MAX_URI];
    int length = snprintf(resource, sizeof(resource), "%s%s%s", path, query ? "?" : "", query ? query : "");
    if (length < 0 || (size_t)length >= sizeof(resource) || !path_safe(path)) {
        evhttp_uri_free(uri);
        return NULL;
    }
    struct route *slot = NULL;
    time_t timestamp = now();
    for (size_t i = 0; i < MAX_ROUTES; i++) {
        struct route *r = &g->routes[i];
        if (r->id && r->expires > timestamp && r->address.s_addr == address.s_addr &&
            r->port == port && r->application == application && !strcmp(r->path, resource)) {
            slot = r;
            break;
        }
        if (!slot && (!r->id || r->expires <= timestamp))
            slot = r;
    }
    if (slot) {
        if (!slot->id || slot->expires <= timestamp) {
            memset(slot, 0, sizeof(*slot));
            slot->id = ++g->next_id;
        }
        slot->address = address;
        slot->port = (unsigned short)port;
        slot->application = application;
        memcpy(slot->path, resource, (size_t)length + 1);
        slot->expires = timestamp + ROUTE_LIFETIME;
    }
    evhttp_uri_free(uri);
    return slot;
}

static int route_url(struct gateway *g, const struct route *r, char *out, size_t size)
{
    int length = snprintf(out, size, "http://[%s]:%u/dial/%" PRIu64 "%s",
        g->text6, g->http_port, r->id, r->path);
    return length > 0 && (size_t)length < size;
}

static struct route *find_route(struct gateway *g, const char *resource, const char **path)
{
    if (strncmp(resource, "/dial/", 6) || !isdigit((unsigned char)resource[6]))
        return NULL;
    char *end;
    errno = 0;
    uint64_t id = strtoull(resource + 6, &end, 10);
    if (errno || !id || *end != '/')
        return NULL;
    for (size_t i = 0; i < MAX_ROUTES; i++) {
        struct route *r = &g->routes[i];
        if (r->id != id || r->expires <= now())
            continue;
        size_t length = strlen(r->path);
        int matches = !strcmp(r->path, end);
        if (r->application)
            matches = !strncmp(r->path, end, length) &&
                (r->path[length - 1] == '/' || end[length] == '/' || end[length] == '?' || end[length] == 0);
        char raw_path[MAX_URI];
        size_t path_length = strcspn(end, "?");
        if (path_length >= sizeof(raw_path))
            return NULL;
        memcpy(raw_path, end, path_length);
        raw_path[path_length] = 0;
        if (!matches || !path_safe(raw_path))
            return NULL;
        *path = end;
        return r;
    }
    return NULL;
}

static void forget_request(struct request *r)
{
    struct request **link = &r->gateway->requests;
    while (*link && *link != r)
        link = &(*link)->next;
    if (*link)
        *link = r->next;
    r->gateway->request_count--;
    free(r);
}

static void copy_headers(struct evkeyvalq *to, const struct evkeyvalq *from,
    const char *const *names)
{
    for (size_t i = 0; names[i]; i++) {
        const char *value = evhttp_find_header(from, names[i]);
        if (value)
            evhttp_add_header(to, names[i], value);
    }
}

static void http_response(struct evhttp_request *back, void *argument)
{
    struct request *r = argument;
    struct gateway *g = r->gateway;
    r->back = NULL;
    if (!evhttp_request_get_connection(r->front)) {
        evhttp_request_free(r->front);
        goto done;
    }
    if (!back || !evhttp_request_get_response_code(back)) {
        if (g->verbose)
            fprintf(stderr, "dial-ipv6: HTTP %s %s backend status unavailable\n",
                r->method == EVHTTP_REQ_POST ? "POST" : r->method == EVHTTP_REQ_GET ? "GET" : "other",
                r->route.application ? "application" : "description");
        evhttp_send_error(r->front, 502, "DIAL device unavailable");
        goto done;
    }
    struct evkeyvalq *input = evhttp_request_get_input_headers(back);
    if (g->verbose)
        fprintf(stderr, "dial-ipv6: HTTP %s %s backend status %d\n",
            r->method == EVHTTP_REQ_POST ? "POST" : r->method == EVHTTP_REQ_GET ? "GET" : "other",
            r->route.application ? "application" : "description",
            evhttp_request_get_response_code(back));
    struct evkeyvalq *output = evhttp_request_get_output_headers(r->front);
    static const char *const names[] = {
        "Content-Type", "Cache-Control", "Expires", "ETag", "Last-Modified", "Allow", "API-Version",
        "Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
        "Access-Control-Allow-Headers", "Access-Control-Max-Age", NULL
    };
    copy_headers(output, input, names);
    evhttp_add_header(output, "Connection", "close");
    const char *application = evhttp_find_header(input, "Application-URL");
    const char *location = evhttp_find_header(input, "Location");
    char rewritten[MAX_URI + 128];
    if (application) {
        struct route *app = register_route(g, application, r->route.address, 1);
        if (!app || !route_url(g, app, rewritten, sizeof(rewritten))) {
            evhttp_send_error(r->front, 502, "Invalid DIAL application endpoint");
            goto done;
        }
        evhttp_add_header(output, "Application-URL", rewritten);
    }
    if (location) {
        if (location[0] == '/' && location[1] != '/') {
            int length = snprintf(rewritten, sizeof(rewritten), "http://[%s]:%u/dial/%" PRIu64 "%s",
                g->text6, g->http_port, r->route.id, location);
            if (length < 0 || (size_t)length >= sizeof(rewritten)) {
                evhttp_send_error(r->front, 502, "Invalid DIAL redirect");
                goto done;
            }
        } else if (!strncasecmp(location, "http://", 7)) {
            struct route *redirect = register_route(g, location, r->route.address, 1);
            if (!redirect || !route_url(g, redirect, rewritten, sizeof(rewritten))) {
                evhttp_send_error(r->front, 502, "Invalid DIAL redirect");
                goto done;
            }
        } else {
            /* Relative references stay under /dial/ID/ when resolved by the client. */
            struct evhttp_uri *relative = evhttp_uri_parse(location);
            if (!relative || evhttp_uri_get_scheme(relative) || evhttp_uri_get_host(relative)) {
                if (relative)
                    evhttp_uri_free(relative);
                evhttp_send_error(r->front, 502, "Invalid DIAL redirect");
                goto done;
            }
            evhttp_uri_free(relative);
            if (strlen(location) >= sizeof(rewritten)) {
                evhttp_send_error(r->front, 502, "Invalid DIAL redirect");
                goto done;
            }
            strcpy(rewritten, location);
        }
        evhttp_add_header(output, "Location", rewritten);
    }
    evhttp_send_reply(r->front, evhttp_request_get_response_code(back),
        evhttp_request_get_response_code_line(back), evhttp_request_get_input_buffer(back));
done:
    evhttp_connection_free_on_completion(r->connection);
    forget_request(r);
}

static void http_request(struct evhttp_request *front, void *argument)
{
    struct gateway *g = argument;
    struct evhttp_connection *front_connection = evhttp_request_get_connection(front);
    const struct sockaddr *address = evhttp_connection_get_addr(front_connection);
    if (!address || address->sa_family != AF_INET6 ||
        !client_allowed(g, (const struct sockaddr_in6 *)address)) {
        evhttp_send_error(front, 403, "Client is not on the configured network");
        return;
    }
    const char *resource = evhttp_request_get_uri(front);
    const char *path;
    struct route *route = find_route(g, resource, &path);
    if (!route) {
        evhttp_send_error(front, 404, "Unknown or expired DIAL endpoint");
        return;
    }
    enum evhttp_cmd_type method = evhttp_request_get_command(front);
    if (!route->application && method != EVHTTP_REQ_GET && method != EVHTTP_REQ_HEAD) {
        evhttp_send_error(front, 405, "Device descriptions are read-only");
        return;
    }
    if (g->request_count >= MAX_REQUESTS) {
        evhttp_send_error(front, 503, "DIAL gateway is busy");
        return;
    }
    struct request *r = calloc(1, sizeof(*r));
    if (!r) {
        evhttp_send_error(front, 503, "DIAL gateway is busy");
        return;
    }
    r->gateway = g;
    r->front = front;
    r->route = *route;
    r->method = method;
    char target[INET_ADDRSTRLEN], authority[64];
    inet_ntop(AF_INET, &route->address, target, sizeof(target));
    snprintf(authority, sizeof(authority), "%s:%u", target, route->port);
    r->connection = evhttp_connection_base_new(g->base, NULL, target, route->port);
    if (!r->connection) {
        free(r);
        evhttp_send_error(front, 503, "DIAL gateway is busy");
        return;
    }
    evhttp_connection_set_family(r->connection, AF_INET);
    evhttp_connection_set_local_address(r->connection, g->text4);
    evhttp_connection_set_retries(r->connection, 0);
    evhttp_connection_set_timeout(r->connection, 15);
    evhttp_connection_set_max_headers_size(r->connection, 16384);
    evhttp_connection_set_max_body_size(r->connection, 65536);
    r->back = evhttp_request_new(http_response, r);
    if (!r->back) {
        evhttp_connection_free(r->connection);
        free(r);
        evhttp_send_error(front, 503, "DIAL gateway is busy");
        return;
    }
    static const char *const names[] = {
        "Content-Type", "Accept", "Access-Control-Request-Method",
        "Access-Control-Request-Headers", NULL
    };
    struct evkeyvalq *output = evhttp_request_get_output_headers(r->back);
    copy_headers(output, evhttp_request_get_input_headers(front), names);
    const char *origin = evhttp_find_header(evhttp_request_get_input_headers(front), "Origin");
    for (size_t i = 0; origin && i < g->forward_origin_count; i++)
        if (!strcmp(origin, g->forward_origins[i])) {
            evhttp_add_header(output, "Origin", origin);
            break;
        }
    evhttp_add_header(output, "Host", authority);
    evhttp_add_header(output, "Connection", "close");
    evhttp_add_header(output, "User-Agent", "udpbroadcastrelay-dial-ipv6/1");
    if (g->verbose)
        fprintf(stderr, "dial-ipv6: proxying HTTP %s %s request\n",
            method == EVHTTP_REQ_POST ? "POST" : method == EVHTTP_REQ_GET ? "GET" : "other",
            route->application ? "application" : "description");
    evbuffer_add_buffer(evhttp_request_get_output_buffer(r->back), evhttp_request_get_input_buffer(front));
    evhttp_request_own(front);
    r->next = g->requests;
    g->requests = r;
    g->request_count++;
    if (evhttp_make_request(r->connection, r->back, method, path) < 0) {
        evhttp_connection_free(r->connection);
        evhttp_send_error(front, 502, "DIAL device unavailable");
        forget_request(r);
    }
}

static int send_reply(struct gateway *g, const struct sockaddr_in6 *peer,
    const char *packet, size_t length)
{
    struct iovec iov = {.iov_base = (void *)packet, .iov_len = length};
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct in6_pktinfo))]; } control;
    memset(&control, 0, sizeof(control));
    struct msghdr message = {
        .msg_name = (void *)peer, .msg_namelen = sizeof(*peer),
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = IPPROTO_IPV6;
    cmsg->cmsg_type = IPV6_PKTINFO;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    struct in6_pktinfo *info = (struct in6_pktinfo *)CMSG_DATA(cmsg);
    info->ipi6_ifindex = g->client_index;
    info->ipi6_addr = g->address6;
    return sendmsg(g->socket6, &message, 0) == (ssize_t)length;
}

static void discovery_reply(evutil_socket_t fd, short events, void *argument)
{
    (void)events;
    struct gateway *g = argument;
    char packet[MAX_PACKET + 1], st[128], usn[512], location[MAX_URI];
    struct sockaddr_in peer;
    socklen_t peer_size = sizeof(peer);
    ssize_t length = recvfrom(fd, packet, MAX_PACKET, MSG_TRUNC, (struct sockaddr *)&peer, &peer_size);
    if (length <= 0 || length > MAX_PACKET || memchr(packet, 0, (size_t)length))
        return;
    packet[length] = 0;
    time_t timestamp = now();
    int waiting = 0;
    for (size_t i = 0; i < MAX_SEARCHES; i++)
        waiting |= g->searches[i].expires > timestamp;
    /* Some servers answer from a fresh UDP socket, not from UDP port 1900. */
    if (!waiting || peer.sin_family != AF_INET || !peer.sin_port ||
        (peer.sin_addr.s_addr & g->mask4.s_addr) != (g->address4.s_addr & g->mask4.s_addr) ||
        peer.sin_addr.s_addr == g->address4.s_addr ||
        strncmp(packet, "HTTP/1.1 200 ", 13) || !strstr(packet, "\r\n\r\n") ||
        !header(packet, "ST", st, sizeof(st)) || strcmp(st, DIAL_ST) ||
        !header(packet, "USN", usn, sizeof(usn)) || !*usn ||
        !header(packet, "LOCATION", location, sizeof(location)))
        return;
    struct route *route = register_route(g, location, peer.sin_addr, 0);
    char url[MAX_URI + 128];
    if (!route || !route_url(g, route, url, sizeof(url)))
        return;
    /* Rebuild discovery headers, replacing LOCATION without touching device identity. */
    struct evbuffer *response = evbuffer_new();
    if (!response)
        return;
    evbuffer_add_printf(response, "HTTP/1.1 200 OK\r\nST: %s\r\nUSN: %s\r\n"
        "LOCATION: %s\r\nCACHE-CONTROL: max-age=60\r\nEXT:\r\n\r\n", st, usn, url);
    size_t response_length = evbuffer_get_length(response);
    const char *data = (const char *)evbuffer_pullup(response, -1);
    int sent = 0;
    if (data)
        for (size_t i = 0; i < MAX_SEARCHES; i++)
            if (g->searches[i].expires > timestamp) {
                struct search *s = &g->searches[i];
                sent += s->clat
                    ? dial_clat_reply(&g->clat, &s->clat_peer, data, response_length)
                    : send_reply(g, &s->peer, data, response_length);
            }
    evbuffer_free(response);
    if (g->verbose)
        fprintf(stderr, "dial-ipv6: relayed DIAL discovery response to %d client(s)\n", sent);
}

static int valid_search(const char *packet, size_t length, int clat)
{
    char st[128], man[128], mx[16];
    if (memchr(packet, 0, length) || strncmp(packet, "M-SEARCH * HTTP/1.1\r\n", 21) ||
        !strstr(packet, "\r\n\r\n") || !header(packet, "ST", st, sizeof(st)) ||
        (strcmp(st, DIAL_ST) && (clat || strcmp(st, "ssdp:all"))) ||
        !header(packet, "MAN", man, sizeof(man)) || strcasecmp(man, "\"ssdp:discover\""))
        return 0;
    /* Keep the raw-socket path narrow, including the discovery wait bound. */
    return !clat || (header(packet, "MX", mx, sizeof(mx)) &&
        strlen(mx) == 1 && mx[0] >= '1' && mx[0] <= '5');
}

static void start_search(struct gateway *g, const struct search *peer)
{
    struct search *slot = NULL;
    time_t timestamp = now();
    for (size_t i = 0; i < MAX_SEARCHES; i++) {
        struct search *s = &g->searches[i];
        int same = s->clat == peer->clat && (peer->clat
            ? s->clat_peer.port == peer->clat_peer.port &&
                s->clat_peer.address.s_addr == peer->clat_peer.address.s_addr &&
                !memcmp(s->clat_peer.mac, peer->clat_peer.mac, 6)
            : s->peer.sin6_port == peer->peer.sin6_port &&
                s->peer.sin6_scope_id == peer->peer.sin6_scope_id &&
                !memcmp(&s->peer.sin6_addr, &peer->peer.sin6_addr, sizeof(s->peer.sin6_addr)));
        if (s->expires > timestamp && same) {
            slot = s;
            break;
        }
        if (!slot && s->expires <= timestamp)
            slot = s;
    }
    if (!slot)
        return;
    *slot = *peer;
    slot->expires = timestamp + SEARCH_LIFETIME;
    if (g->last_search == timestamp)
        return;
    /* A canonical request hides phone headers and only discovers DIAL servers. */
    static const char request[] = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: " DIAL_ST "\r\n\r\n";
    struct sockaddr_in destination = {.sin_family = AF_INET, .sin_port = htons(SSDP_PORT)};
    inet_pton(AF_INET, "239.255.255.250", &destination.sin_addr);
    if (sendto(g->socket4, request, sizeof(request) - 1, 0,
        (struct sockaddr *)&destination, sizeof(destination)) == sizeof(request) - 1) {
        g->last_search = timestamp;
        if (g->verbose)
            fprintf(stderr, "dial-ipv6: sent canonical DIAL search (%s client)\n",
                peer->clat ? "CLAT" : "IPv6");
    }
}

static void discovery_request(evutil_socket_t fd, short events, void *argument)
{
    (void)events;
    struct gateway *g = argument;
    char packet[MAX_PACKET + 1];
    struct search peer = {0};
    union { struct cmsghdr align; unsigned char bytes[256]; } control;
    struct iovec iov = {.iov_base = packet, .iov_len = MAX_PACKET};
    struct msghdr message = {
        .msg_name = &peer.peer, .msg_namelen = sizeof(peer.peer), .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = control.bytes, .msg_controllen = sizeof(control.bytes)
    };
    ssize_t length = recvmsg(fd, &message, 0);
    if (length <= 0 || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
        return;
    packet[length] = 0;
    int correct_interface = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c))
        if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO &&
            c->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
            struct in6_pktinfo *info = (struct in6_pktinfo *)CMSG_DATA(c);
            correct_interface = info->ipi6_ifindex == g->client_index;
        }
    if (correct_interface && peer.peer.sin6_family == AF_INET6 && peer.peer.sin6_port &&
        client_allowed(g, &peer.peer) && valid_search(packet, (size_t)length, 0))
        start_search(g, &peer);
}

static void clat_request(evutil_socket_t fd, short events, void *argument)
{
    (void)fd; (void)events;
    struct gateway *g = argument;
    struct search peer = {.clat = 1};
    char packet[MAX_PACKET + 1];
    ssize_t length = dial_clat_receive(&g->clat, &peer.clat_peer, packet, sizeof(packet));
    if (length > 0 && valid_search(packet, (size_t)length, 1))
        start_search(g, &peer);
}

static int sockets(struct gateway *g)
{
    int yes = 1;
    g->socket6 = socket(AF_INET6, SOCK_DGRAM, 0);
    g->socket4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (g->socket6 < 0 || g->socket4 < 0)
        return 0;
    if (setsockopt(g->socket6, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) < 0 ||
        setsockopt(g->socket6, IPPROTO_IPV6, IPV6_RECVPKTINFO, &yes, sizeof(yes)) < 0)
        return 0;
    struct sockaddr_in6 listen6 = {.sin6_family = AF_INET6, .sin6_port = htons(SSDP_PORT)};
    if (bind(g->socket6, (struct sockaddr *)&listen6, sizeof(listen6)) < 0)
        return 0;
    struct ipv6_mreq group = {.ipv6mr_interface = g->client_index};
    inet_pton(AF_INET6, "ff02::c", &group.ipv6mr_multiaddr);
    if (setsockopt(g->socket6, IPPROTO_IPV6, IPV6_JOIN_GROUP, &group, sizeof(group)) < 0)
        return 0;
    struct sockaddr_in listen4 = {
        .sin_family = AF_INET, .sin_port = htons(g->reply_port), .sin_addr = g->address4
    };
    unsigned char ttl = 2, loop = 0;
    if (bind(g->socket4, (struct sockaddr *)&listen4, sizeof(listen4)) < 0 ||
        setsockopt(g->socket4, IPPROTO_IP, IP_MULTICAST_IF, &g->address4, sizeof(g->address4)) < 0 ||
        setsockopt(g->socket4, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0 ||
        setsockopt(g->socket4, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0 ||
        evutil_make_socket_nonblocking(g->socket6) < 0 || evutil_make_socket_nonblocking(g->socket4) < 0)
        return 0;
    return 1;
}

static void stop(evutil_socket_t signal_number, short events, void *argument)
{
    (void)signal_number;
    (void)events;
    event_base_loopbreak(((struct gateway *)argument)->base);
}

int dial_ipv6_main(int argc, char **argv)
{
    struct gateway g = {
        .http_port = 1901, .reply_port = 1901, .socket6 = -1, .socket4 = -1,
        .clat = {.fd = -1}
    };
    int address_given = 0, result = 1;
    for (int i = 1; i < argc; i++) {
        const char *option = argv[i];
        if (!strcmp(option, "--dial-ipv6"))
            continue;
        if (!strcmp(option, "--help") || !strcmp(option, "-h")) {
            usage(argv[0]);
            return 0;
        }
        if (!strcmp(option, "-d")) {
            g.verbose = 1;
            continue;
        }
        if (!strcmp(option, "--clat-discovery")) {
            g.clat_discovery = 1;
            continue;
        }
        if (!strcmp(option, "--forward-origin")) {
            if (i + 1 == argc || g.forward_origin_count == MAX_FORWARD_ORIGINS ||
                !valid_origin(argv[i + 1])) {
                fprintf(stderr, "dial-ipv6: invalid --forward-origin (maximum %d; values must be 1..%d visible non-whitespace bytes)\n",
                    MAX_FORWARD_ORIGINS, MAX_URI - 1);
                return 1;
            }
            strcpy(g.forward_origins[g.forward_origin_count++], argv[++i]);
            continue;
        }
        if (i + 1 == argc) {
            usage(argv[0]);
            return 1;
        }
        const char *value = argv[++i];
        if (!strcmp(option, "--client-dev"))
            g.client_dev = value;
        else if (!strcmp(option, "--server-dev"))
            g.server_dev = value;
        else if (!strcmp(option, "--listen-address"))
            address_given = inet_pton(AF_INET6, value, &g.address6) == 1;
        else if (!strcmp(option, "--http-port") && port_number(value, &g.http_port))
            continue;
        else if (!strcmp(option, "--reply-port") && port_number(value, &g.reply_port))
            continue;
        else {
            fprintf(stderr, "dial-ipv6: invalid option/value: %s\n", option);
            return 1;
        }
    }
    if (!g.client_dev || !g.server_dev || !strcmp(g.client_dev, g.server_dev) || !address_given ||
        IN6_IS_ADDR_UNSPECIFIED(&g.address6) || IN6_IS_ADDR_LINKLOCAL(&g.address6) ||
        IN6_IS_ADDR_MULTICAST(&g.address6) || IN6_IS_ADDR_V4MAPPED(&g.address6)) {
        usage(argv[0]);
        return 1;
    }
    inet_ntop(AF_INET6, &g.address6, g.text6, sizeof(g.text6));
    if (!interfaces(&g)) {
        fprintf(stderr, "dial-ipv6: interfaces must be up, the listen address must belong to the client interface, and the server interface needs IPv4\n");
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    g.base = event_base_new();
    if (!g.base || !sockets(&g)) {
        perror("dial-ipv6: socket setup");
        goto cleanup;
    }
    if (g.clat_discovery && !dial_clat_open(&g.clat, g.client_index, g.address4)) {
        perror("dial-ipv6: CLAT discovery socket (requires Linux and CAP_NET_RAW)");
        goto cleanup;
    }
    g.http = evhttp_new(g.base);
    if (!g.http)
        goto cleanup;
    evhttp_set_max_headers_size(g.http, 16384);
    evhttp_set_max_body_size(g.http, 65536);
    evhttp_set_timeout(g.http, 30);
    evhttp_set_default_content_type(g.http, NULL);
    evhttp_set_allowed_methods(g.http,
        EVHTTP_REQ_GET | EVHTTP_REQ_HEAD | EVHTTP_REQ_POST | EVHTTP_REQ_DELETE | EVHTTP_REQ_OPTIONS);
    evhttp_set_gencb(g.http, http_request, &g);
    if (evhttp_bind_socket(g.http, g.text6, g.http_port) < 0) {
        perror("dial-ipv6: HTTP listener");
        goto cleanup;
    }
    if (g.clat_discovery && !dial_clat_drop_capabilities()) {
        perror("dial-ipv6: dropping CLAT startup capabilities");
        goto cleanup;
    }
    g.read6 = event_new(g.base, g.socket6, EV_READ | EV_PERSIST, discovery_request, &g);
    g.read4 = event_new(g.base, g.socket4, EV_READ | EV_PERSIST, discovery_reply, &g);
    if (g.clat_discovery) {
        g.read_clat = event_new(g.base, g.clat.fd, EV_READ | EV_PERSIST, clat_request, &g);
        if (!g.read_clat || event_add(g.read_clat, NULL))
            goto cleanup;
    }
    g.term = evsignal_new(g.base, SIGTERM, stop, &g);
    g.interrupt = evsignal_new(g.base, SIGINT, stop, &g);
    if (!g.read6 || !g.read4 || !g.term || !g.interrupt ||
        event_add(g.read6, NULL) || event_add(g.read4, NULL) ||
        event_add(g.term, NULL) || event_add(g.interrupt, NULL))
        goto cleanup;
    fprintf(stderr, "dial-ipv6: %s IPv6 clients -> %s IPv4 DIAL servers; HTTP [%s]:%u, reply UDP %u\n",
        g.client_dev, g.server_dev, g.text6, g.http_port, g.reply_port);
    if (g.clat_discovery)
        fprintf(stderr, "dial-ipv6: CLAT discovery enabled on %s; IPv6 HTTP only; startup capabilities dropped\n",
            g.client_dev);
    result = event_base_dispatch(g.base) < 0;
cleanup:
    while (g.requests) {
        struct request *r = g.requests;
        evhttp_cancel_request(r->back);
        evhttp_connection_free(r->connection);
        struct evhttp_connection *front = evhttp_request_get_connection(r->front);
        if (front)
            evhttp_connection_free(front);
        evhttp_request_free(r->front);
        forget_request(r);
    }
    if (g.read6) event_free(g.read6);
    if (g.read4) event_free(g.read4);
    if (g.read_clat) event_free(g.read_clat);
    if (g.term) event_free(g.term);
    if (g.interrupt) event_free(g.interrupt);
    if (g.http) evhttp_free(g.http);
    if (g.socket6 >= 0) close(g.socket6);
    if (g.socket4 >= 0) close(g.socket4);
    if (g.clat.fd >= 0) close(g.clat.fd);
    if (g.base) event_base_free(g.base);
    return result;
}
