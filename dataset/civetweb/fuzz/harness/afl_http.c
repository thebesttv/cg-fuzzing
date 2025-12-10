/* AFL harness for civetweb URL parsing
 * Tests the mg_url_decode and mg_get_var functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Disable SSL to simplify the build */
#define NO_SSL

#define CIVETWEB_API static
#include "civetweb.c"  /* Include implementation for static functions */

#ifdef __AFL_FUZZ_TESTCASE_LEN
  #include <unistd.h>
  __AFL_FUZZ_INIT();
#endif

int main(int argc, char **argv) {
#ifdef __AFL_FUZZ_TESTCASE_LEN
    __AFL_INIT();
    unsigned char *data = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int size = __AFL_FUZZ_TESTCASE_LEN;
#else
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *data = malloc(size + 1);
    if (!data) { fclose(f); return 1; }
    fread(data, 1, size, f);
    data[size] = 0;
    fclose(f);
    {
#endif
        if (size < 1 || size > 65536) {
#ifdef __AFL_FUZZ_TESTCASE_LEN
            continue;
#else
            goto cleanup;
#endif
        }

        /* Test URL decode */
        char decoded[65536];
        int decoded_len = mg_url_decode((const char *)data, size, decoded, sizeof(decoded), 0);
        (void)decoded_len;

        /* Test variable extraction */
        char var_buf[1024];
        int var_len = mg_get_var2((const char *)data, size, "test", var_buf, sizeof(var_buf), 0);
        (void)var_len;

        /* Test cookie extraction */
        var_len = mg_get_cookie((const char *)data, "session", var_buf, sizeof(var_buf));
        (void)var_len;

#ifdef __AFL_FUZZ_TESTCASE_LEN
    }
#else
    }
cleanup:
    free(data);
#endif
    return 0;
}
