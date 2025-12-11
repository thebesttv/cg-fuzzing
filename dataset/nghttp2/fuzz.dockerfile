FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract nghttp2 v1.68.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/nghttp2/nghttp2/releases/download/v1.68.0/nghttp2-1.68.0.tar.gz && \
    tar -xzf nghttp2-1.68.0.tar.gz && \
    rm nghttp2-1.68.0.tar.gz

WORKDIR /src/nghttp2-1.68.0

# Configure with static linking - library only
RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure \
        --disable-shared \
        --enable-static \
        --enable-lib-only

# Build nghttp2 library
RUN make -j$(nproc)

# Create a simple HPACK decoder test program
RUN echo '#include <stdio.h>' > hd_decode.c && \
    echo '#include <stdlib.h>' >> hd_decode.c && \
    echo '#include <stdint.h>' >> hd_decode.c && \
    echo '#include <nghttp2/nghttp2.h>' >> hd_decode.c && \
    echo 'int main(int argc, char **argv) {' >> hd_decode.c && \
    echo '    if (argc < 2) { return 1; }' >> hd_decode.c && \
    echo '    FILE *f = fopen(argv[1], "rb");' >> hd_decode.c && \
    echo '    if (!f) { return 1; }' >> hd_decode.c && \
    echo '    fseek(f, 0, SEEK_END);' >> hd_decode.c && \
    echo '    long fsize = ftell(f);' >> hd_decode.c && \
    echo '    fseek(f, 0, SEEK_SET);' >> hd_decode.c && \
    echo '    if (fsize <= 0 || fsize > 1024*1024) { fclose(f); return 0; }' >> hd_decode.c && \
    echo '    uint8_t *data = malloc(fsize);' >> hd_decode.c && \
    echo '    if (!data) { fclose(f); return 1; }' >> hd_decode.c && \
    echo '    fread(data, 1, fsize, f);' >> hd_decode.c && \
    echo '    fclose(f);' >> hd_decode.c && \
    echo '    nghttp2_hd_inflater *inflater;' >> hd_decode.c && \
    echo '    nghttp2_hd_inflate_new(&inflater);' >> hd_decode.c && \
    echo '    nghttp2_nv nv;' >> hd_decode.c && \
    echo '    int inflate_flags;' >> hd_decode.c && \
    echo '    ssize_t rv;' >> hd_decode.c && \
    echo '    uint8_t *in = data;' >> hd_decode.c && \
    echo '    size_t inlen = fsize;' >> hd_decode.c && \
    echo '    while (inlen > 0) {' >> hd_decode.c && \
    echo '        rv = nghttp2_hd_inflate_hd2(inflater, &nv, &inflate_flags, in, inlen, 1);' >> hd_decode.c && \
    echo '        if (rv < 0) break;' >> hd_decode.c && \
    echo '        in += rv;' >> hd_decode.c && \
    echo '        inlen -= rv;' >> hd_decode.c && \
    echo '        if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) break;' >> hd_decode.c && \
    echo '    }' >> hd_decode.c && \
    echo '    nghttp2_hd_inflate_del(inflater);' >> hd_decode.c && \
    echo '    free(data);' >> hd_decode.c && \
    echo '    return 0;' >> hd_decode.c && \
    echo '}' >> hd_decode.c

# Compile the test program with afl-clang-lto
RUN afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
    -I. -Ilib/includes \
    hd_decode.c lib/.libs/libnghttp2.a \
    -o /out/hd_decode

# Build CMPLOG version
WORKDIR /src
RUN rm -rf nghttp2-1.68.0 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/nghttp2/nghttp2/releases/download/v1.68.0/nghttp2-1.68.0.tar.gz && \
    tar -xzf nghttp2-1.68.0.tar.gz && \
    rm nghttp2-1.68.0.tar.gz

WORKDIR /src/nghttp2-1.68.0

RUN CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --enable-lib-only

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Create the same test program for CMPLOG
RUN echo '#include <stdio.h>' > hd_decode.c && \
    echo '#include <stdlib.h>' >> hd_decode.c && \
    echo '#include <stdint.h>' >> hd_decode.c && \
    echo '#include <nghttp2/nghttp2.h>' >> hd_decode.c && \
    echo 'int main(int argc, char **argv) {' >> hd_decode.c && \
    echo '    if (argc < 2) { return 1; }' >> hd_decode.c && \
    echo '    FILE *f = fopen(argv[1], "rb");' >> hd_decode.c && \
    echo '    if (!f) { return 1; }' >> hd_decode.c && \
    echo '    fseek(f, 0, SEEK_END);' >> hd_decode.c && \
    echo '    long fsize = ftell(f);' >> hd_decode.c && \
    echo '    fseek(f, 0, SEEK_SET);' >> hd_decode.c && \
    echo '    if (fsize <= 0 || fsize > 1024*1024) { fclose(f); return 0; }' >> hd_decode.c && \
    echo '    uint8_t *data = malloc(fsize);' >> hd_decode.c && \
    echo '    if (!data) { fclose(f); return 1; }' >> hd_decode.c && \
    echo '    fread(data, 1, fsize, f);' >> hd_decode.c && \
    echo '    fclose(f);' >> hd_decode.c && \
    echo '    nghttp2_hd_inflater *inflater;' >> hd_decode.c && \
    echo '    nghttp2_hd_inflate_new(&inflater);' >> hd_decode.c && \
    echo '    nghttp2_nv nv;' >> hd_decode.c && \
    echo '    int inflate_flags;' >> hd_decode.c && \
    echo '    ssize_t rv;' >> hd_decode.c && \
    echo '    uint8_t *in = data;' >> hd_decode.c && \
    echo '    size_t inlen = fsize;' >> hd_decode.c && \
    echo '    while (inlen > 0) {' >> hd_decode.c && \
    echo '        rv = nghttp2_hd_inflate_hd2(inflater, &nv, &inflate_flags, in, inlen, 1);' >> hd_decode.c && \
    echo '        if (rv < 0) break;' >> hd_decode.c && \
    echo '        in += rv;' >> hd_decode.c && \
    echo '        inlen -= rv;' >> hd_decode.c && \
    echo '        if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) break;' >> hd_decode.c && \
    echo '    }' >> hd_decode.c && \
    echo '    nghttp2_hd_inflate_del(inflater);' >> hd_decode.c && \
    echo '    free(data);' >> hd_decode.c && \
    echo '    return 0;' >> hd_decode.c && \
    echo '}' >> hd_decode.c

# Compile CMPLOG version
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -static -Wl,--allow-multiple-definition \
    -I. -Ilib/includes \
    hd_decode.c lib/.libs/libnghttp2.a \
    -o /out/hd_decode.cmplog

# Copy fuzzing resources
COPY nghttp2/fuzz/dict /out/dict
COPY nghttp2/fuzz/in /out/in
COPY nghttp2/fuzz/fuzz.sh /out/fuzz.sh
COPY nghttp2/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/hd_decode /out/hd_decode.cmplog && \
    file /out/hd_decode

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing nghttp2 HPACK decoder'"]
