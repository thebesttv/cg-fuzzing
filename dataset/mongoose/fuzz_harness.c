#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mongoose.h"

#define MAX_INPUT_SIZE (1024 * 1024)

int main(int argc, char *argv[]) {
    FILE *f;
    char *input = NULL;
    size_t input_size;
    struct mg_http_message hm;
    struct mg_str body;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open file: %s\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    input_size = ftell(f);
    rewind(f);

    if (input_size == 0 || input_size > MAX_INPUT_SIZE) {
        fclose(f);
        return 0;
    }

    input = (char *)malloc(input_size + 1);
    if (!input) {
        fclose(f);
        return 1;
    }

    if (fread(input, 1, input_size, f) != input_size) {
        free(input);
        fclose(f);
        return 1;
    }
    input[input_size] = 0;
    fclose(f);

    /* Parse as HTTP request */
    memset(&hm, 0, sizeof(hm));
    mg_http_parse(input, input_size, &hm);

    /* Try to get various headers */
    mg_http_get_header(&hm, "Content-Type");
    mg_http_get_header(&hm, "Content-Length");
    mg_http_get_header(&hm, "Host");
    mg_http_get_header(&hm, "User-Agent");
    mg_http_get_header(&hm, "Accept");
    mg_http_get_header(&hm, "Connection");

    /* Try to get request body */
    body = hm.body;
    (void)body;

    /* Try URL parsing */
    if (hm.uri.len > 0) {
        struct mg_str query = hm.query;
        (void)query;
    }

    free(input);
    return 0;
}
