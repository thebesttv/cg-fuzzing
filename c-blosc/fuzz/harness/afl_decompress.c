#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "blosc.h"

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
    fclose(f);
    {
#endif
        size_t nbytes, cbytes, blocksize;
        
        if (size < BLOSC_MIN_HEADER_LENGTH) {
#ifdef __AFL_FUZZ_TESTCASE_LEN
            continue;
#else
            goto cleanup;
#endif
        }

        blosc_cbuffer_sizes(data, &nbytes, &cbytes, &blocksize);
        if (cbytes != (size_t)size || nbytes == 0) {
#ifdef __AFL_FUZZ_TESTCASE_LEN
            continue;
#else
            goto cleanup;
#endif
        }

        if (blosc_cbuffer_validate(data, size, &nbytes) != 0) {
#ifdef __AFL_FUZZ_TESTCASE_LEN
            continue;
#else
            goto cleanup;
#endif
        }

        void *output = malloc(nbytes);
        if (output != NULL) {
            blosc_decompress(data, output, nbytes);
            free(output);
        }
#ifdef __AFL_FUZZ_TESTCASE_LEN
    }
#else
    }
cleanup:
    free(data);
#endif
    return 0;
}
