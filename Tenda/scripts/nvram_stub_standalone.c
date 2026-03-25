/*
 * nvram_stub_standalone.c - Self-contained NVRAM stub (no libc dependency)
 *
 * Implements all needed string functions inline to avoid any libc linking.
 * Used as LD_PRELOAD or direct replacement for libnvram.so in Tenda rootfs.
 *
 * Compile:
 *   arm-linux-gnueabi-gcc -shared -fPIC -nostdlib -o libnvram.so nvram_stub_standalone.c
 */

#define MAX_ENTRIES 512
#define MAX_KEY 128
#define MAX_VAL 512

/* ---- Inline string functions (no libc needed) ---- */

static int my_strlen(const char *s) {
    int n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static int my_strcmp(const char *a, const char *b) {
    if (!a && !b) return 0;
    if (!a) return -1;
    if (!b) return 1;
    while (*a && *b && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static void my_strncpy(char *dst, const char *src, int n) {
    int i;
    if (!dst || !src) return;
    for (i = 0; i < n - 1 && src[i]; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

/* ---- ARM syscall for debug output ---- */

static void my_write(int fd, const char *buf, int len) {
    /* ARM Linux syscall: write = 4 */
    __asm__ volatile (
        "mov r7, #4\n"
        "mov r0, %0\n"
        "mov r1, %1\n"
        "mov r2, %2\n"
        "svc #0\n"
        :
        : "r"(fd), "r"(buf), "r"(len)
        : "r0", "r1", "r2", "r7", "memory"
    );
}

static void dbg(const char *msg) {
    my_write(2, "[nvram] ", 8);
    my_write(2, msg, my_strlen(msg));
    my_write(2, "\n", 1);
}

/* ---- NVRAM store ---- */

static struct {
    char key[MAX_KEY];
    char val[MAX_VAL];
} store[MAX_ENTRIES];

static int cnt = 0;
static int ready = 0;

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
    for (i = 0; defs[i].k && cnt < MAX_ENTRIES; i++) {
        my_strncpy(store[cnt].key, defs[i].k, MAX_KEY);
        my_strncpy(store[cnt].val, defs[i].v, MAX_VAL);
        cnt++;
    }
    dbg("store initialized");
}

static int find_key(const char *key) {
    int i;
    for (i = 0; i < cnt; i++)
        if (my_strcmp(store[i].key, key) == 0)
            return i;
    return -1;
}

/* ---- Exported NVRAM API ---- */

int nvram_init(void) {
    init_store();
    dbg("nvram_init()");
    return 0;
}

char *nvram_get(const char *key) {
    int idx;
    static char empty[1] = "";
    init_store();
    if (!key) return empty;
    idx = find_key(key);
    if (idx >= 0) return store[idx].val;
    return empty;
}

int nvram_set(const char *key, const char *val) {
    int idx;
    init_store();
    if (!key) return -1;
    idx = find_key(key);
    if (idx >= 0) {
        if (val) my_strncpy(store[idx].val, val, MAX_VAL);
        else store[idx].val[0] = '\0';
        return 0;
    }
    if (cnt < MAX_ENTRIES) {
        my_strncpy(store[cnt].key, key, MAX_KEY);
        if (val) my_strncpy(store[cnt].val, val, MAX_VAL);
        else store[cnt].val[0] = '\0';
        cnt++;
        return 0;
    }
    return -1;
}

int nvram_unset(const char *key) {
    int idx;
    init_store();
    if (!key) return -1;
    idx = find_key(key);
    if (idx >= 0) store[idx].val[0] = '\0';
    return 0;
}

int nvram_commit(void) {
    return 0;
}

int nvram_getall(char *buf, int sz) {
    int i, off = 0;
    init_store();
    if (!buf || sz <= 0) return -1;
    for (i = 0; i < cnt && off < sz - 1; i++) {
        int kl = my_strlen(store[i].key);
        int vl = my_strlen(store[i].val);
        if (off + kl + 1 + vl + 1 >= sz) break;
        my_strncpy(buf + off, store[i].key, kl + 1);
        off += kl;
        buf[off++] = '=';
        my_strncpy(buf + off, store[i].val, vl + 1);
        off += vl;
        buf[off++] = '\0';
    }
    if (off < sz) buf[off] = '\0';
    return off;
}
