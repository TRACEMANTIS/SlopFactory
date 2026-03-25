/*
 * nvram_stub.c - NVRAM stub library for Tenda httpd emulation
 *
 * Provides fake NVRAM backend so httpd can start in QEMU without
 * real hardware. Returns sensible defaults for critical config keys.
 *
 * Compile: arm-linux-gnueabi-gcc -shared -fPIC -o libnvram.so nvram_stub.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Simple key-value store */
#define MAX_ENTRIES 512
#define MAX_KEY_LEN 128
#define MAX_VAL_LEN 512

static struct {
    char key[MAX_KEY_LEN];
    char val[MAX_VAL_LEN];
} nvram_store[MAX_ENTRIES];

static int nvram_count = 0;
static int initialized = 0;

/* Default NVRAM values for httpd to start */
static struct {
    const char *key;
    const char *val;
} defaults[] = {
    /* System */
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

    /* WAN */
    {"wan.mode", "dhcp"},
    {"wan.ip", "[REDACTED-IP]"},
    {"wan.mask", "255.255.255.0"},
    {"wan.gw", "[REDACTED-IP]"},
    {"wan.dns1", "[REDACTED-IP]"},
    {"wan.dns2", "[REDACTED-IP]"},
    {"wan.mac", "00:11:22:33:44:56"},

    /* WiFi */
    {"wl.ssid", "Tenda_TEST"},
    {"wl.pwd", "12345678"},
    {"wl.security", "wpapsk"},
    {"wl.encrypt", "aes"},
    {"wl.channel", "6"},
    {"wl0.ssid", "Tenda_TEST"},
    {"wl0.pwd", "12345678"},
    {"wl1.ssid", "Tenda_TEST_5G"},
    {"wl1.pwd", "12345678"},

    /* Firewall */
    {"firewall.en", "0"},
    {"firewall.level", "low"},

    /* HTTP */
    {"http.port", "80"},
    {"http.lan.en", "1"},
    {"http.wan.en", "0"},

    /* Time */
    {"sys.timezone", "UTC"},
    {"sys.ntp", "pool.ntp.org"},

    /* Misc */
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

    {NULL, NULL}
};

static void load_defaults(void) {
    int i;
    if (initialized) return;
    initialized = 1;

    for (i = 0; defaults[i].key != NULL && nvram_count < MAX_ENTRIES; i++) {
        strncpy(nvram_store[nvram_count].key, defaults[i].key, MAX_KEY_LEN - 1);
        strncpy(nvram_store[nvram_count].val, defaults[i].val, MAX_VAL_LEN - 1);
        nvram_count++;
    }

    fprintf(stderr, "[nvram_stub] Loaded %d default entries\n", nvram_count);
}

static int find_entry(const char *key) {
    int i;
    for (i = 0; i < nvram_count; i++) {
        if (strcmp(nvram_store[i].key, key) == 0) {
            return i;
        }
    }
    return -1;
}

/* nvram_init - initialize NVRAM backend */
int nvram_init(void) {
    load_defaults();
    fprintf(stderr, "[nvram_stub] nvram_init() called\n");
    return 0;
}

/* nvram_get - retrieve value by key */
char *nvram_get(const char *key) {
    int idx;
    load_defaults();

    if (key == NULL) return "";

    idx = find_entry(key);
    if (idx >= 0) {
        return nvram_store[idx].val;
    }

    /* Return empty string for unknown keys instead of NULL */
    fprintf(stderr, "[nvram_stub] nvram_get(\"%s\") = (not found, returning \"\")\n", key);
    return "";
}

/* nvram_set - store value */
int nvram_set(const char *key, const char *val) {
    int idx;
    load_defaults();

    if (key == NULL) return -1;

    fprintf(stderr, "[nvram_stub] nvram_set(\"%s\", \"%s\")\n", key, val ? val : "(null)");

    idx = find_entry(key);
    if (idx >= 0) {
        if (val) {
            strncpy(nvram_store[idx].val, val, MAX_VAL_LEN - 1);
            nvram_store[idx].val[MAX_VAL_LEN - 1] = '\0';
        } else {
            nvram_store[idx].val[0] = '\0';
        }
        return 0;
    }

    /* Add new entry */
    if (nvram_count < MAX_ENTRIES) {
        strncpy(nvram_store[nvram_count].key, key, MAX_KEY_LEN - 1);
        if (val) {
            strncpy(nvram_store[nvram_count].val, val, MAX_VAL_LEN - 1);
        }
        nvram_count++;
        return 0;
    }

    return -1;
}

/* nvram_unset - remove a key */
int nvram_unset(const char *key) {
    int idx;
    load_defaults();

    if (key == NULL) return -1;

    fprintf(stderr, "[nvram_stub] nvram_unset(\"%s\")\n", key);

    idx = find_entry(key);
    if (idx >= 0) {
        nvram_store[idx].val[0] = '\0';
    }
    return 0;
}

/* nvram_commit - persist changes (no-op for stub) */
int nvram_commit(void) {
    fprintf(stderr, "[nvram_stub] nvram_commit() called (no-op)\n");
    return 0;
}

/* nvram_getall - dump all entries */
int nvram_getall(char *buf, int count) {
    int i, offset = 0;
    load_defaults();

    fprintf(stderr, "[nvram_stub] nvram_getall(buf, %d)\n", count);

    if (buf == NULL || count <= 0) return -1;

    for (i = 0; i < nvram_count && offset < count - 1; i++) {
        int len = snprintf(buf + offset, count - offset, "%s=%s",
                          nvram_store[i].key, nvram_store[i].val);
        if (len < 0 || offset + len + 1 >= count) break;
        offset += len + 1;  /* include null terminator */
    }

    if (offset < count) buf[offset] = '\0';

    return offset;
}
