#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "src/mjson.h"
#define MAX_INPUT_SIZE (1024 * 1024)
int main(int argc, char *argv[]) {
    FILE *f;
    char *input = NULL;
    size_t input_size;
    double dval;
    int ival;
    int bval;
    char buf[256];
    const char *p;
    int n;
    if (argc < 2) { fprintf(stderr, "Usage: %s <input_file>\n", argv[0]); return 1; }
    f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "Cannot open file: %s\n", argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    input_size = ftell(f);
    rewind(f);
    if (input_size == 0 || input_size > MAX_INPUT_SIZE) { fclose(f); return 0; }
    input = (char *)malloc(input_size + 1);
    if (!input) { fclose(f); return 1; }
    if (fread(input, 1, input_size, f) != input_size) { free(input); fclose(f); return 1; }
    fclose(f);
    input[input_size] = 0;
    mjson_get_number(input, (int)input_size, "$", &dval);
    mjson_get_bool(input, (int)input_size, "$", &bval);
    mjson_get_string(input, (int)input_size, "$", buf, sizeof(buf));
    mjson_find(input, (int)input_size, "$", &p, &n);
    mjson_get_number(input, (int)input_size, "$.a", &dval);
    mjson_get_string(input, (int)input_size, "$.b", buf, sizeof(buf));
    mjson_find(input, (int)input_size, "$.c[0]", &p, &n);
    free(input);
    return 0;
}
