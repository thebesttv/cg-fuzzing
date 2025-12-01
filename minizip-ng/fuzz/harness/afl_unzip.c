/* AFL harness for minizip-ng based on unzip_fuzzer.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mz.h"
#include "mz_strm.h"
#include "mz_strm_mem.h"
#include "mz_zip.h"
#include "mz_zip_rw.h"

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
        void *mem_stream = NULL;
        void *reader = NULL;
        int32_t err = MZ_OK;

        if (size < 4) {
#ifdef __AFL_FUZZ_TESTCASE_LEN
            continue;
#else
            goto cleanup;
#endif
        }

        mem_stream = mz_stream_mem_create();
        if (mem_stream == NULL) {
#ifdef __AFL_FUZZ_TESTCASE_LEN
            continue;
#else
            goto cleanup;
#endif
        }

        mz_stream_mem_set_buffer(mem_stream, (void *)data, size);
        mz_stream_open(mem_stream, NULL, MZ_OPEN_MODE_READ);

        reader = mz_zip_reader_create();
        if (reader == NULL) {
            mz_stream_mem_delete(&mem_stream);
#ifdef __AFL_FUZZ_TESTCASE_LEN
            continue;
#else
            goto cleanup;
#endif
        }

        err = mz_zip_reader_open(reader, mem_stream);
        if (err == MZ_OK) {
            mz_zip_file *file_info = NULL;
            err = mz_zip_reader_goto_first_entry(reader);
            while (err == MZ_OK) {
                mz_zip_reader_entry_get_info(reader, &file_info);
                err = mz_zip_reader_goto_next_entry(reader);
            }
            mz_zip_reader_close(reader);
        }

        mz_zip_reader_delete(&reader);
        mz_stream_mem_delete(&mem_stream);
#ifdef __AFL_FUZZ_TESTCASE_LEN
    }
#else
    }
cleanup:
    free(data);
#endif
    return 0;
}
