FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool pkg-config libogg-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract speex 1.2.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/speex/archive/refs/tags/Speex-1.2.1.tar.gz && \
    tar -xzf Speex-1.2.1.tar.gz && \
    rm Speex-1.2.1.tar.gz

WORKDIR /src/speex-Speex-1.2.1

# Generate configure script
RUN ./autogen.sh

# Configure with afl-clang-fast
RUN CC=afl-clang-fast \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-oggtest --disable-binaries

# Build speex library
RUN make -j$(nproc)

# Build speexdec with afl-clang-fast
RUN cd src && \
    afl-clang-fast -O2 -I../include -I.. -DHAVE_CONFIG_H -Wl,--allow-multiple-definition \
        speexdec.c getopt.c getopt1.c wav_io.c \
        -L../libspeex/.libs -lspeex -logg -lm \
        -o speexdec

# Copy binary
RUN cp src/speexdec /out/speexdec

# Build CMPLOG version
WORKDIR /src
RUN rm -rf speex-Speex-1.2.1 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/speex/archive/refs/tags/Speex-1.2.1.tar.gz && \
    tar -xzf Speex-1.2.1.tar.gz && \
    rm Speex-1.2.1.tar.gz

WORKDIR /src/speex-Speex-1.2.1

# Generate configure script
RUN ./autogen.sh

# Configure with afl-clang-fast and CMPLOG
RUN CC=afl-clang-fast \
    CFLAGS="-O2" \
    LDFLAGS="-Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --disable-oggtest --disable-binaries

# Build speex library
RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build speexdec with CMPLOG
RUN cd src && \
    AFL_LLVM_CMPLOG=1 afl-clang-fast -O2 -I../include -I.. -DHAVE_CONFIG_H -Wl,--allow-multiple-definition \
        speexdec.c getopt.c getopt1.c wav_io.c \
        -L../libspeex/.libs -lspeex -logg -lm \
        -o speexdec

# Copy CMPLOG binary
RUN cp src/speexdec /out/speexdec.cmplog

# Copy fuzzing resources
COPY speex/fuzz/dict /out/dict
COPY speex/fuzz/in /out/in
COPY speex/fuzz/fuzz.sh /out/fuzz.sh
COPY speex/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/speexdec /out/speexdec.cmplog && \
    file /out/speexdec && \
    /out/speexdec --version || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing speex'"]
