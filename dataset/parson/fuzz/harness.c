/*
 * Simple harness for fuzzing parson JSON library.
 * This harness reads a JSON file and attempts to parse it.
 */
#include <stdio.h>
#include <stdlib.h>
#include "parson.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <json_file>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    
    /* Parse the JSON file */
    JSON_Value *root = json_parse_file(filename);
    
    if (root != NULL) {
        /* Successfully parsed - free the memory */
        json_value_free(root);
        return 0;
    }
    
    /* Parse failed (invalid JSON) */
    return 1;
}
