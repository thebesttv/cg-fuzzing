#include "llhttp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int on_message_complete(llhttp_t* parser) {
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <http_request_file>\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *buf = malloc(len + 1);
    fread(buf, 1, len, f);
    buf[len] = 0;
    fclose(f);
    
    llhttp_t parser;
    llhttp_settings_t settings;
    
    llhttp_settings_init(&settings);
    settings.on_message_complete = on_message_complete;
    
    llhttp_init(&parser, HTTP_BOTH, &settings);
    
    enum llhttp_errno err = llhttp_execute(&parser, buf, len);
    
    if (err != HPE_OK) {
        fprintf(stderr, "Parse error: %s %s\n", llhttp_errno_name(err), llhttp_get_error_reason(&parser));
    }
    
    free(buf);
    return 0;
}
