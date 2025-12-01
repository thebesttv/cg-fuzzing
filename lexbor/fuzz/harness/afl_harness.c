#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lexbor/html/html.h>

#ifdef __AFL_FUZZ_TESTCASE_LEN
  #include <unistd.h>
  __AFL_FUZZ_INIT();
#endif

int main(int argc, char **argv) {
#ifdef __AFL_FUZZ_TESTCASE_LEN
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
#else
    // Read from file for non-AFL use
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(len + 1);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, len, f);
    fclose(f);
    {
#endif
        lxb_html_document_t *document = lxb_html_document_create();
        if (document != NULL) {
            lxb_html_document_parse(document, buf, len);
            lxb_html_document_destroy(document);
        }
#ifdef __AFL_FUZZ_TESTCASE_LEN
    }
#else
    }
    free(buf);
#endif
    return 0;
}
