#!/bin/bash
# Script to create fuzzing harness for picohttpparser

cat > fuzz_harness.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "picohttpparser.h"
#define MAX_INPUT_SIZE (1024 * 1024)
#define MAX_HEADERS 100
int main(int argc, char *argv[]) {
    FILE *f;
    char *input = NULL;
    size_t input_size;
    const char *method, *path, *msg;
    size_t method_len, path_len, msg_len, num_headers;
    int minor_version, status;
    struct phr_header headers[MAX_HEADERS];
    struct phr_chunked_decoder decoder;
    size_t bufsz;
    char *buf_copy;
    if (argc < 2) { fprintf(stderr, "Usage: %s <input_file>\n", argv[0]); return 1; }
    f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "Cannot open file: %s\n", argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    input_size = ftell(f);
    rewind(f);
    if (input_size == 0 || input_size > MAX_INPUT_SIZE) { fclose(f); return 0; }
    input = (char *)malloc(input_size);
    if (!input) { fclose(f); return 1; }
    if (fread(input, 1, input_size, f) != input_size) { free(input); fclose(f); return 1; }
    fclose(f);
    /* Parse as HTTP request */
    num_headers = MAX_HEADERS;
    phr_parse_request(input, input_size, &method, &method_len, &path, &path_len, &minor_version, headers, &num_headers, 0);
    /* Parse as HTTP response */
    num_headers = MAX_HEADERS;
    phr_parse_response(input, input_size, &minor_version, &status, &msg, &msg_len, headers, &num_headers, 0);
    /* Parse as headers only */
    num_headers = MAX_HEADERS;
    phr_parse_headers(input, input_size, headers, &num_headers, 0);
    /* Decode chunked encoding */
    buf_copy = (char *)malloc(input_size);
    if (buf_copy) {
        memcpy(buf_copy, input, input_size);
        memset(&decoder, 0, sizeof(decoder));
        bufsz = input_size;
        phr_decode_chunked(&decoder, buf_copy, &bufsz);
        free(buf_copy);
    }
    free(input);
    return 0;
}
EOF
