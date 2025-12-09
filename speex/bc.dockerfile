FROM svftools/svf:latest

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
WORKDIR /home/SVF-tools
RUN wget https://github.com/xiph/speex/archive/refs/tags/Speex-1.2.1.tar.gz && \
    tar -xzf Speex-1.2.1.tar.gz && \
    rm Speex-1.2.1.tar.gz

WORKDIR /home/SVF-tools/speex-Speex-1.2.1

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
RUN mkdir -p ~/bc && \
    extract-bc src/speexdec && \
    mv src/speexdec.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
