FROM svftools/svf:latest

# 1. Install WLLVM
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download cabextract source code (v1.11)
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.cabextract.org.uk/cabextract-1.11.tar.gz && \
    tar -xzf cabextract-1.11.tar.gz && \
    rm cabextract-1.11.tar.gz

WORKDIR /home/SVF-tools/cabextract-1.11

# 3. Build with WLLVM using autotools
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# 4. Extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc cabextract && \
    mv cabextract.bc ~/bc/

# 5. Verify
RUN ls -la ~/bc/
