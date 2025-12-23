FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y autoconf automake libtool file pkg-config libogg-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract speex 1.2.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: speex" > /work/proj && \
    echo "version: 1.2.1" >> /work/proj && \
    echo "source: https://github.com/xiph/speex/archive/refs/tags/Speex-1.2.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/xiph/speex/archive/refs/tags/Speex-1.2.1.tar.gz && \
    tar -xzf Speex-1.2.1.tar.gz && \
    mv Speex-1.2.1 build && \
    rm Speex-1.2.1.tar.gz

WORKDIR /work/build

# Generate configure script
RUN ./autogen.sh

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-oggtest --disable-binaries

# Build speex library
RUN make -j$(nproc)

# Build speexdec manually with static linking
RUN cd src && \
    wllvm -g -O0 -Xclang -disable-llvm-passes -I../include -I.. -DHAVE_CONFIG_H -static -Wl,--allow-multiple-definition \
        speexdec.c getopt.c getopt1.c wav_io.c \
        -L../libspeex/.libs -lspeex -logg -lm \
        -o speexdec

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/speexdec && \
    mv src/speexdec.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
