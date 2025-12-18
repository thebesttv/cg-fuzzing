FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract groonga v15.2.1
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/groonga/groonga/releases/download/v15.2.1/groonga-15.2.1.tar.gz && \
    tar -xzf groonga-15.2.1.tar.gz && \
    rm groonga-15.2.1.tar.gz

WORKDIR /home/SVF-tools/groonga-15.2.1

# Install build dependencies (file for extract-bc, development libraries for groonga)
RUN apt-get update && \
    apt-get install -y file pkg-config libmecab-dev liblz4-dev zlib1g-dev libzmq3-dev libevent-dev libmsgpack-dev rapidjson-dev libxxhash-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Disable MeCab as it doesn't have static library
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static --disable-document --without-mecab

# Build groonga
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from binaries
RUN mkdir -p ~/bc && \
    for bin in src/groonga src/grndb src/grnslap src/grndump; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            basename_bc=$(basename "$bin").bc && \
            mv "${bin}.bc" ~/bc/"${basename_bc}" 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
