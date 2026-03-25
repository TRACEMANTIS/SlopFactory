/*
 * nvram_stub_minimal.c - Minimal NVRAM stub for Tenda httpd emulation
 *
 * Uses only functions available in uClibc (no glibc dependency).
 * Compiled against target rootfs sysroot.
 *
 * Compile:
 *   arm-linux-gnueabi-gcc -shared -fPIC \
 *     --sysroot=/path/to/squashfs-root \
 *     -o libnvram.so nvram_stub_minimal.c
 */

/* Forward-declare only what we need (avoid pulling in system headers) */
extern int strcmp(const char *, const char *);
extern char *strncpy(char *, const char *, unsigned int);
extern int strlen(const char *);
extern int snprintf(char *, unsigned int, const char *, ...);
extern int write(int, const void *, unsigned int);

#define MAX_ENTRIES 512
#define MAX_KEY_LEN 128
#define MAX_VAL_LEN 512

static struct {
    char key[MAX_KEY_LEN];
    char val[MAX_VAL_LEN];
} store[MAX_ENTRIES];

static int count = 0;
static int ready = 0;

/* Minimal debug output */
static void dbg(const char *msg) {
    int len = 0;
    const char *p = msg;
    while (*p++) len++;
    write(2, "[nvram] ", 8);
    write(2, msg, len);
    write(2, "\n", 1);
}

static struct { const char *k; const char *v; } defs[] = {
    {"sys.username", "admin"},
    {"sys.userpass", ""},
    {"sys.model", "AC15"},
    {"sys.fwver", "V15.03.05.19"},
    {"sys.sn", "000000000000"},
    {"lan.ip", "[REDACTED-IP]"},
    {"lan.mask", "255.255.255.0"},
    {"lan.dhcp.en", "1"},
    {"lan.dhcp.start", "[REDACTED-IP]"},
    {"lan.dhcp.end", "[REDACTED-IP]"},
    {"lan.dhcp.lease", "86400"},
    {"lan.mac", "00:11:22:33:44:55"},
    {"wan.mode", "dhcp"},
    {"wan.ip", "[REDACTED-IP]"},
    {"wan.mask", "255.255.255.0"},
    {"wan.gw", "[REDACTED-IP]"},
    {"wan.dns1", "[REDACTED-IP]"},
    {"wan.dns2", "[REDACTED-IP]"},
    {"wan.mac", "00:11:22:33:44:56"},
    {"wl.ssid", "Tenda_TEST"},
    {"wl.pwd", "12345678"},
    {"wl.security", "wpapsk"},
    {"wl.encrypt", "aes"},
    {"wl.channel", "6"},
    {"wl0.ssid", "Tenda_TEST"},
    {"wl0.pwd", "12345678"},
    {"wl1.ssid", "Tenda_TEST_5G"},
    {"wl1.pwd", "12345678"},
    {"firewall.en", "0"},
    {"firewall.level", "low"},
    {"http.port", "80"},
    {"http.lan.en", "1"},
    {"http.wan.en", "0"},
    {"sys.timezone", "UTC"},
    {"sys.ntp", "pool.ntp.org"},
    {"upnp.en", "1"},
    {"dmz.en", "0"},
    {"pptp.en", "0"},
    {"ipsec.en", "0"},
    {"telnet.en", "0"},
    {"wps.pin", "16677883"},
    {"usb.en", "0"},
    {"guest.en", "0"},
    {"wl_phy_type", "n"},
    {"restore_defaults", "0"},
    {"boardnum", "0"},
    {"boardtype", "0"},
    {"wl_unit", "0"},
    {"wl0_radio", "1"},
    {"wl1_radio", "1"},
    {"time_zone", "0"},
    {0, 0}
};

static void init_store(void) {
    int i;
    if (ready) return;
    ready = 1;
    for (i = 0; defs[i].k && count < MAX_ENTRIES; i++) {
        strncpy(store[count].key, defs[i].k, MAX_KEY_LEN - 1);
        strncpy(store[count].val, defs[i].v, MAX_VAL_LEN - 1);
        count++;
    }
    dbg("store initialized");
}

static int find(const char *key) {
    int i;
    for (i = 0; i < count; i++)
        if (strcmp(store[i].key, key) == 0)
            return i;
    return -1;
}

int nvram_init(void) {
    init_store();
    dbg("nvram_init()");
    return 0;
}

char *nvram_get(const char *key) {
    int idx;
    init_store();
    if (!key) return "";
    idx = find(key);
    if (idx >= 0) return store[idx].val;
    /* Return empty for unknown keys */
    return "";
}

int nvram_set(const char *key, const char *val) {
    int idx;
    init_store();
    if (!key) return -1;

    idx = find(key);
    if (idx >= 0) {
        if (val) strncpy(store[idx].val, val, MAX_VAL_LEN - 1);
        else store[idx].val[0] = '\0';
        return 0;
    }
    if (count < MAX_ENTRIES) {
        strncpy(store[count].key, key, MAX_KEY_LEN - 1);
        if (val) strncpy(store[count].val, val, MAX_VAL_LEN - 1);
        count++;
        return 0;
    }
    return -1;
}

int nvram_unset(const char *key) {
    int idx;
    init_store();
    if (!key) return -1;
    idx = find(key);
    if (idx >= 0) store[idx].val[0] = '\0';
    return 0;
}

int nvram_commit(void) {
    dbg("nvram_commit()");
    return 0;
}

int nvram_getall(char *buf, int sz) {
    int i, off = 0;
    init_store();
    if (!buf || sz <= 0) return -1;
    for (i = 0; i < count && off < sz - 1; i++) {
        int kl = strlen(store[i].key);
        int vl = strlen(store[i].val);
        if (off + kl + 1 + vl + 1 >= sz) break;
        strncpy(buf + off, store[i].key, kl);
        off += kl;
        buf[off++] = '=';
        strncpy(buf + off, store[i].val, vl);
        off += vl;
        buf[off++] = '\0';
    }
    if (off < sz) buf[off] = '\0';
    return off;
}
