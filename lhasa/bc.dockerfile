FROM svftools/svf:latest

# 1. Install WLLVM
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file autoconf automake libtool pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download lhasa source code (v0.4.0 - latest stable)
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/fragglet/lhasa/releases/download/v0.4.0/lhasa-0.4.0.tar.gz && \
    tar -xzf lhasa-0.4.0.tar.gz && \
    rm lhasa-0.4.0.tar.gz

WORKDIR /home/SVF-tools/lhasa-0.4.0

# 3. Build with WLLVM using autotools
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# 4. Extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/lha && \
    mv src/lha.bc ~/bc/

# 5. Verify
RUN ls -la ~/bc/
