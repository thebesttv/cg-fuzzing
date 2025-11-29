/* Wren interpreter harness for fuzzing */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wren.h"

/* Maximum file size to prevent memory exhaustion (100KB) */
#define MAX_FILE_SIZE 102400

static void writeFn(WrenVM* vm, const char* text) {
    printf("%s", text);
}

static void errorFn(WrenVM* vm, WrenErrorType errorType,
                    const char* module, int line, const char* msg) {
    fprintf(stderr, "[%s line %d] %s\n", module, line, msg);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <wren_file>\n", argv[0]);
        return 1;
    }

    FILE* fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open file: %s\n", argv[1]);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0 || size > MAX_FILE_SIZE) {
        fclose(fp);
        return 0;
    }

    char* source = (char*)malloc(size + 1);
    if (!source) {
        fclose(fp);
        return 1;
    }

    fread(source, 1, size, fp);
    fclose(fp);
    source[size] = '\0';

    WrenConfiguration config;
    wrenInitConfiguration(&config);
    config.writeFn = writeFn;
    config.errorFn = errorFn;

    WrenVM* vm = wrenNewVM(&config);
    wrenInterpret(vm, "main", source);
    wrenFreeVM(vm);

    free(source);
    return 0;
}
