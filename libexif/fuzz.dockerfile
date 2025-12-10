FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget gettext libpopt-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and build libexif v0.6.25 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/libexif/libexif/releases/download/v0.6.25/libexif-0.6.25.tar.gz && \
    tar -xzf libexif-0.6.25.tar.gz && \
    rm libexif-0.6.25.tar.gz

WORKDIR /src/libexif-0.6.25

# Build libexif with afl-clang-lto
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)
RUN make install

# Download and build exif CLI tool
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/libexif/exif/releases/download/exif-0_6_22-release/exif-0.6.22.tar.gz && \
    tar -xzf exif-0.6.22.tar.gz && \
    rm exif-0.6.22.tar.gz

WORKDIR /src/exif-0.6.22

# Build exif CLI with afl-clang-lto
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -I/usr/local/include" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -L/usr/local/lib" \
    PKG_CONFIG_PATH="/usr/local/lib/pkgconfig" \
    POPT_CFLAGS="-I/usr/include" \
    POPT_LIBS="-lpopt" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Install the exif binary
RUN cp exif/exif /out/exif

# Build CMPLOG version
WORKDIR /src
RUN rm -rf libexif-0.6.25 exif-0.6.22

# Rebuild libexif with CMPLOG
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/libexif/libexif/releases/download/v0.6.25/libexif-0.6.25.tar.gz && \
    tar -xzf libexif-0.6.25.tar.gz && \
    rm libexif-0.6.25.tar.gz

WORKDIR /src/libexif-0.6.25

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN make install

# Rebuild exif CLI with CMPLOG
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/libexif/exif/releases/download/exif-0_6_22-release/exif-0.6.22.tar.gz && \
    tar -xzf exif-0.6.22.tar.gz && \
    rm exif-0.6.22.tar.gz

WORKDIR /src/exif-0.6.22

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -I/usr/local/include" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -L/usr/local/lib" \
    PKG_CONFIG_PATH="/usr/local/lib/pkgconfig" \
    POPT_CFLAGS="-I/usr/include" \
    POPT_LIBS="-lpopt" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp exif/exif /out/exif.cmplog

# Copy fuzzing resources
COPY libexif/fuzz/dict /out/dict
COPY libexif/fuzz/in /out/in
COPY libexif/fuzz/fuzz.sh /out/fuzz.sh
COPY libexif/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/exif /out/exif.cmplog && \
    file /out/exif && \
    /out/exif --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing exif'"]
