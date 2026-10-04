/* oracle_native.c — poison-free S channel (final: scan-based GOT patch + diagnostics). */
#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <android/log.h>

#define TAG "ADJ9S"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

static void *(*real_fopen)(const char *, const char *);
static size_t (*real_fread)(void *, size_t, size_t, void *);
static int (*real_fclose)(void *);

static void *urandom_stream;
static volatile int installed;
static volatile int inject_n;
static unsigned char inject_buf[8];

static void *real_addr_of(const char *name) {
    void *h = dlopen("libc.so", RTLD_NOW);
    if (!h) return NULL;
    void *a = dlsym(h, name);
    dlclose(h);
    return a;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void reload_inject_file(void) {
    FILE *f = fopen("/data/local/tmp/adj9_sinject", "r");
    if (!f) { inject_n = 0; return; }
    char line[64];
    size_t n = fread(line, 1, sizeof(line) - 1, f);
    fclose(f);
    line[n] = 0;
    int j = 0, hi = -1;
    unsigned char b[8] = {0};
    for (size_t i = 0; i < n && j < 8; i++) {
        int v = hexval(line[i]);
        if (v < 0) continue;
        if (hi < 0) hi = v;
        else { b[j++] = (unsigned char)((hi << 4) | v); hi = -1; }
    }
    if (j == 8) {
        memcpy(inject_buf, b, 8);
        inject_n = 8;
        LOGI("inject armed: %02x%02x%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
    }
}

static void *my_fopen(const char *path, const char *mode) {
    void *r = real_fopen(path, mode);
    if (r && path && strstr(path, "urandom")) {
        urandom_stream = r;
        LOGI("urandom opened handle=%p", r);
        reload_inject_file();
    }
    return r;
}

static size_t my_fread(void *buf, size_t sz, size_t n, void *f) {
    size_t r = real_fread(buf, sz, n, f);
    if (f == urandom_stream && r == 8) {
        unsigned char *p = (unsigned char *)buf;
        unsigned int S = (unsigned)p[0] | ((unsigned)p[1] << 8) |
                         ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
        LOGI("S=%08x raw=%02x%02x%02x%02x%02x%02x%02x%02x",
             S, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        if (inject_n == 8) {
            memcpy(buf, inject_buf, 8);
            unsigned int S2 = (unsigned)inject_buf[0] | ((unsigned)inject_buf[1] << 8) |
                              ((unsigned)inject_buf[2] << 16) | ((unsigned)inject_buf[3] << 24);
            LOGI("INJECTED S=%08x", S2);
        }
    }
    return r;
}

static ssize_t (*real_read)(int, void *, size_t);
static ssize_t my_read(int fd, void *buf, size_t count) {
    ssize_t r = real_read(fd, buf, count);
    if (r == 8 && count == 8) {
        unsigned char *p = (unsigned char *)buf;
        unsigned int S = (unsigned)p[0] | ((unsigned)p[1] << 8) |
                         ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
        LOGI("S=%08x raw=%02x%02x%02x%02x%02x%02x%02x%02x",
             S, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
        if (inject_n == 8) {
            memcpy(buf, inject_buf, 8);
            unsigned int S2 = (unsigned)inject_buf[0] | ((unsigned)inject_buf[1] << 8) |
                              ((unsigned)inject_buf[2] << 16) | ((unsigned)inject_buf[3] << 24);
            LOGI("INJECTED S=%08x", S2);
        }
    }
    return r;
}

static int my_fclose(void *f) {
    if (f == urandom_stream) urandom_stream = NULL;
    return real_fclose(f);
}

/* scan every RW mapping of libsigner for a GOT slot holding the real
 * imported function address; overwrite it with the hook. */
static int patch_got_scan(const char *symname, void *hook, void **saved) {
    void *real = real_addr_of(symname);
    if (!real) return -1;
    FILE *mf = fopen("/proc/self/maps", "r");
    if (!mf) return -2;
    char line[512];
    unsigned long ranges[64][2];
    int nr = 0;
    while (fgets(line, sizeof(line), mf) && nr < 64) {
        if (!strstr(line, "split_config.arm64_v8a.apk")) continue;
        if (!strstr(line, "rw")) continue;
        unsigned long a, b;
        if (sscanf(line, "%lx-%lx", &a, &b) == 2) {
            ranges[nr][0] = a; ranges[nr][1] = b; nr++;
        }
    }
    fclose(mf);
    int patched = 0;
    long pagesz = 4096;
    LOGI("scan %s: real=%p nr=%d", symname, real, nr);
    {
        FILE *df = fopen("/data/data/com.penti.app/files/got_dump.bin", "ab");
        if (df) {
            fwrite(&real, sizeof(void*), 1, df);
            for (int i = 0; i < nr; i++) {
                unsigned long lo = ranges[i][0], hi = ranges[i][1];
                fwrite(&lo, 8, 1, df); fwrite(&hi, 8, 1, df);
                fwrite((void *)lo, 1, hi - lo, df);
            }
            unsigned long term = 0xDEADBEEFDEADBEEFUL;
            fwrite(&term, 8, 1, df);
            fclose(df);
        }
    }
    for (int i = 0; i < nr; i++) {
        unsigned long lo = ranges[i][0], hi = ranges[i][1];
        for (unsigned long pg = lo & ~(unsigned long)(pagesz - 1); pg < hi; pg += pagesz) {
            mprotect((void *)pg, pagesz, PROT_READ | PROT_WRITE);
        }
        for (unsigned long a = lo; a + 8 <= hi; a += 8) {
            void **slot = (void **)a;
            if (*slot != real) continue;
            *saved = *slot;
            *slot = hook;
            patched++;
            LOGI("GOT %s patched at %lx (orig %p)", symname, a, *saved);
            break;
        }
    }
    return patched ? 0 : -3;
}

static int do_arm(void) {
    char mapsline[512];
    char libp[256] = {0};
    FILE *mf = fopen("/proc/self/maps", "r");
    if (!mf) return -1;
    int total = 0, signer = 0;
    while (fgets(mapsline, sizeof(mapsline), mf)) {
        total++;
        char *p = strstr(mapsline, "split_config.arm64_v8a.apk");
        if (p) {
            signer++;
            char *sp = strchr(mapsline, '/');
            if (sp) {
                char *nl = strchr(sp, '\n');
                if (nl) *nl = 0;
                strncpy(libp, sp, sizeof(libp) - 1);
            }
        }
    }
    fclose(mf);
    LOGI("do_arm scan: total=%d signer=%d libp=%s", total, signer,
         libp[0] ? libp : "-");
    if (!libp[0]) return -2;
    if (installed) return 1;
    LOGI("arming GOT hooks (lib=%s)", libp);
    void *s1 = NULL, *s2 = NULL, *s3 = NULL;
    if (patch_got_scan("fopen", (void *)my_fopen, &s1) == 0) LOGI("fopen hooked");
    if (patch_got_scan("fread", (void *)my_fread, &s2) == 0) LOGI("fread hooked");
    if (patch_got_scan("fclose", (void *)my_fclose, &s3) == 0) LOGI("fclose hooked");
    if (patch_got_scan("read", (void *)my_read, &s3) == 0) LOGI("read hooked");
    installed = 1;
    return 0;
}

JNIEXPORT void JNICALL
Java_com_adj9oracle_Hook_nativeArm(JNIEnv *env, jclass clazz) {
    (void)env; (void)clazz;
    int r = -99;
    /* libsigner maps LAZILY inside the first NLH.a call (System.loadLibrary
     * happens after this hook fires) — poll until it appears. */
    for (int i = 0; i < 150; i++) {
        r = do_arm();
        if (r != -2) break;
        usleep(100 * 1000);
    }
    LOGI("nativeArm -> %d (poll done)", r);
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm; (void)reserved;
    LOGI("oracle_native loaded");
    return JNI_VERSION_1_6;
}
