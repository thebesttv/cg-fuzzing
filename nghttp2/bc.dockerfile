FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract nghttp2 v1.68.0
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/nghttp2/nghttp2/releases/download/v1.68.0/nghttp2-1.68.0.tar.gz && \
    tar -xzf nghttp2-1.68.0.tar.gz && \
    rm nghttp2-1.68.0.tar.gz

WORKDIR /home/SVF-tools/nghttp2-1.68.0

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM - library only
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
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

# Compile the test program with wllvm
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -static -Wl,--allow-multiple-definition \
    -I. -Ilib/includes \
    hd_decode.c lib/.libs/libnghttp2.a \
    -o hd_decode

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc hd_decode && \
    mv hd_decode.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
