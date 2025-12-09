FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libsndfile 1.2.2
WORKDIR /home/SVF-tools
RUN wget https://github.com/libsndfile/libsndfile/releases/download/1.2.2/libsndfile-1.2.2.tar.xz && \
    tar -xJf libsndfile-1.2.2.tar.xz && \
    rm libsndfile-1.2.2.tar.xz

WORKDIR /home/SVF-tools/libsndfile-1.2.2

# Install build dependencies (file for extract-bc, python3 for autogen)
RUN apt-get update && \
    apt-get install -y file autogen libtool pkg-config python3 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Disable external libs (FLAC, Ogg, Vorbis, Opus, mp3) to simplify static linking
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static \
    --disable-external-libs --disable-mpeg

# Build libsndfile
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc programs/sndfile-info && \
    mv programs/sndfile-info.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
