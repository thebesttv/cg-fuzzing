#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "miniz.h"
#define MAX_INPUT_SIZE (1024 * 1024)
int main(int argc, char *argv[]) {
    FILE *f;
    unsigned char *input = NULL;
    unsigned char *output = NULL;
    size_t input_size;
    mz_ulong output_size;
    int result;
    if (argc < 2) { fprintf(stderr, "Usage: %s <input_file>\n", argv[0]); return 1; }
    f = fopen(argv[1], "rb");
    if (!f) { fprintf(stderr, "Cannot open file: %s\n", argv[1]); return 1; }
    fseek(f, 0, SEEK_END);
    input_size = ftell(f);
    rewind(f);
    if (input_size == 0 || input_size > MAX_INPUT_SIZE) { fclose(f); return 0; }
    input = (unsigned char *)malloc(input_size);
    if (!input) { fclose(f); return 1; }
    if (fread(input, 1, input_size, f) != input_size) { free(input); fclose(f); return 1; }
    fclose(f);
    output_size = (mz_ulong)(input_size * 10 + 1024);
    output = (unsigned char *)malloc(output_size);
    if (!output) { free(input); return 1; }
    result = uncompress(output, &output_size, input, (mz_ulong)input_size);
    (void)result;
    {
        mz_stream stream;
        memset(&stream, 0, sizeof(stream));
        stream.next_in = input;
        stream.avail_in = (mz_uint32)input_size;
        stream.next_out = output;
        stream.avail_out = (mz_uint32)(input_size * 10 + 1024);
        if (inflateInit(&stream) == MZ_OK) {
            inflate(&stream, MZ_FINISH);
            inflateEnd(&stream);
        }
    }
    free(output);
    free(input);
    return 0;
}
