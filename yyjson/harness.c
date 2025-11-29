/* yyjson_parse - simple harness for fuzzing yyjson */
#include <stdio.h>
#include <stdlib.h>
#include "yyjson.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <json_file>\n", argv[0]);
        return 1;
    }
    yyjson_read_err err;
    yyjson_doc *doc = yyjson_read_file(argv[1], 0, NULL, &err);
    if (doc) {
        char *json = yyjson_write(doc, 0, NULL);
        if (json) {
            printf("%s\n", json);
            free(json);
        }
        yyjson_doc_free(doc);
    } else {
        fprintf(stderr, "Parse error: %s at pos %zu\n", err.msg, err.pos);
    }
    return 0;
}
