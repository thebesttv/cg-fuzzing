/*
 * Fuzzing harness for frozen JSON parser
 * Reads JSON from a file and parses it using frozen's API
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "frozen.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <json_file>\n", argv[0]);
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

    char *json = malloc(fsize + 1);
    if (!json) {
        fclose(f);
        return 1;
    }

    if (fread(json, 1, fsize, f) != (size_t)fsize) {
        free(json);
        fclose(f);
        return 1;
    }
    fclose(f);
    json[fsize] = '\0';

    /* Parse using json_walk (callback-based parsing) */
    struct json_token t;
    int i;
    for (i = 0; json_scanf_array_elem(json, fsize, "", i, &t) > 0; i++) {
        /* Just walk through the array */
    }

    /* Also try parsing as object */
    const char *p = NULL;
    int len = 0;
    if (json_scanf(json, fsize, "{name: %Q, value: %d}", &p, &len) > 0) {
        if (p) free((void*)p);
    }

    /* Parse with json_walk for callback */
    json_walk(json, fsize, NULL, NULL);

    free(json);
    return 0;
}
