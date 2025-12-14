#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <nghttp2/nghttp2.h>

int main(int argc, char **argv) {
    if (argc < 2) { return 1; }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { return 1; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > 1024*1024) { fclose(f); return 0; }
    uint8_t *data = malloc(fsize);
    if (!data) { fclose(f); return 1; }
    fread(data, 1, fsize, f);
    fclose(f);
    nghttp2_hd_inflater *inflater;
    nghttp2_hd_inflate_new(&inflater);
    nghttp2_nv nv;
    int inflate_flags;
    ssize_t rv;
    uint8_t *in = data;
    size_t inlen = fsize;
    while (inlen > 0) {
        rv = nghttp2_hd_inflate_hd2(inflater, &nv, &inflate_flags, in, inlen, 1);
        if (rv < 0) break;
        in += rv;
        inlen -= rv;
        if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) break;
    }
    nghttp2_hd_inflate_del(inflater);
    free(data);
    return 0;
}
