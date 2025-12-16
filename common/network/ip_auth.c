// ip_auth.c - optional IP allowlist check for KasmVNC websocket handshake
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>   // strncasecmp
#include "websocket.h"

// Same env name as your Python plugin
#define ENV_ALLOWED_IP "USER_CLIENT_IP_ADDRESS"
#define HDR_REAL_IP    "X-Real-IP"

// extra_headers is already used by websocket.c responses
extern char *extra_headers;

// Small sanity check (IPv4/IPv6-ish)
static int is_valid_ip_chars(const char *s, size_t n)
{
    if (!s || n == 0) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isxdigit(c) || c == '.' || c == ':')) return 0;
    }
    return 1;
}

// Find header value from raw HTTP request (case-insensitive header name).
// Writes trimmed value into out. Returns 1 if found, 0 if not found.
static int get_header_value(const char *req, const char *name,
                            char *out, size_t out_sz)
{
    if (!req || !name || !out || out_sz == 0) return 0;

    // Search for "\r\nName:" first (most common)
    char needle[128];
    snprintf(needle, sizeof(needle), "\r\n%s:", name);

    const char *p = strcasestr(req, needle);

    // Could also be the first header line without leading \r\n
    if (!p) {
        size_t namelen = strlen(name);
        if (strncasecmp(req, name, namelen) == 0 && req[namelen] == ':') {
            p = req; // starts at beginning
        } else {
            return 0;
        }
    } else {
        p += 2; // skip "\r\n"
    }

    const char *colon = strchr(p, ':');
    if (!colon) return 0;

    p = colon + 1;
    while (*p == ' ' || *p == '\t') p++;

    const char *end = strstr(p, "\r\n");
    if (!end) end = p + strlen(p);

    // Trim trailing whitespace
    while (end > p && (end[-1] == ' ' || end[-1] == '\t')) end--;

    size_t n = (size_t)(end - p);
    if (n == 0) return 0;
    if (n >= out_sz) n = out_sz - 1;

    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

static void send_403(ws_ctx_t *ws_ctx, const char *msg)
{
    char buf[4096];
    const char *hdrs = extra_headers ? extra_headers : "";

    snprintf(buf, sizeof(buf),
             "HTTP/1.1 403 Forbidden\r\n"
             "Server: KasmVNC/4.0\r\n"
             "Connection: close\r\n"
             "Content-type: text/plain; charset=utf-8\r\n"
             "%s"
             "\r\n"
             "%s",
             hdrs, msg ? msg : "403 Forbidden");

    ws_send(ws_ctx, buf, strlen(buf));
}

// ------------------------------------------------------------
// HOOK TARGET (strong symbol in this file)
// Return: 0 = allow, 1 = denied (and response already sent)
// ------------------------------------------------------------
int kasm_ip_auth_hook(ws_ctx_t *ws_ctx,
                      const char *handshake,
                      const char *origip,
                      const char *ip,
                      const char *url)
{
    (void)origip;
    (void)ip;
    (void)url;

    const char *allowed = getenv(ENV_ALLOWED_IP);
    if (!allowed || allowed[0] == '\0') {
        // env not set => allow
        return 0;
    }

    char real_ip[128];
    if (!get_header_value(handshake, HDR_REAL_IP, real_ip, sizeof(real_ip))) {
        send_403(ws_ctx, "denied: missing X-Real-IP header");
        return 1;
    }

    size_t n = strlen(real_ip);
    if (!is_valid_ip_chars(real_ip, n)) {
        send_403(ws_ctx, "denied: invalid X-Real-IP header");
        return 1;
    }

    if (strcmp(real_ip, allowed) != 0) {
        char msg[256];
        snprintf(msg, sizeof(msg),
                 "denied: your ip is %s, expected %s", real_ip, allowed);
        send_403(ws_ctx, msg);
        return 1;
    }

    return 0; // allow
}
