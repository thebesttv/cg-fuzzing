/*
 * Fuzzing harness for MPack library (MessagePack for C)
 * Reads MessagePack data from a file and parses it using mpack's reader API
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MPACK_READER 1
#define MPACK_EXTENSIONS 1
#include "src/mpack/mpack.h"

/* Recursively parse MessagePack data */
static void parse_node(mpack_reader_t *reader, int depth) {
    if (depth > 64) {
        /* Prevent stack overflow on deeply nested data */
        mpack_reader_flag_error(reader, mpack_error_data);
        return;
    }

    mpack_tag_t tag = mpack_read_tag(reader);
    if (mpack_reader_error(reader) != mpack_ok) {
        return;
    }

    switch (mpack_tag_type(&tag)) {
        case mpack_type_nil:
        case mpack_type_bool:
        case mpack_type_int:
        case mpack_type_uint:
        case mpack_type_float:
        case mpack_type_double:
            /* Simple types - nothing more to do */
            break;

        case mpack_type_str:
            mpack_skip_bytes(reader, mpack_tag_str_length(&tag));
            mpack_done_str(reader);
            break;

        case mpack_type_bin:
            mpack_skip_bytes(reader, mpack_tag_bin_length(&tag));
            mpack_done_bin(reader);
            break;

        case mpack_type_ext:
            mpack_skip_bytes(reader, mpack_tag_ext_length(&tag));
            mpack_done_ext(reader);
            break;

        case mpack_type_array: {
            uint32_t count = mpack_tag_array_count(&tag);
            for (uint32_t i = 0; i < count && mpack_reader_error(reader) == mpack_ok; i++) {
                parse_node(reader, depth + 1);
            }
            mpack_done_array(reader);
            break;
        }

        case mpack_type_map: {
            uint32_t count = mpack_tag_map_count(&tag);
            for (uint32_t i = 0; i < count && mpack_reader_error(reader) == mpack_ok; i++) {
                parse_node(reader, depth + 1);  /* key */
                parse_node(reader, depth + 1);  /* value */
            }
            mpack_done_map(reader);
            break;
        }

        default:
            mpack_reader_flag_error(reader, mpack_error_data);
            break;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <msgpack_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 10*1024*1024) {
        fclose(f);
        return 1;
    }

    char *data = malloc(fsize);
    if (!data) {
        fclose(f);
        return 1;
    }

    if (fread(data, 1, fsize, f) != (size_t)fsize) {
        free(data);
        fclose(f);
        return 1;
    }
    fclose(f);

    /* Parse the MessagePack data */
    mpack_reader_t reader;
    mpack_reader_init_data(&reader, data, fsize);

    while (mpack_reader_remaining(&reader, NULL) > 0 &&
           mpack_reader_error(&reader) == mpack_ok) {
        parse_node(&reader, 0);
    }

    mpack_reader_destroy(&reader);
    free(data);

    return 0;
}
