FROM thebesttv/svf:latest

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

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: cabextract" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: https://www.cabextract.org.uk/cabextract-1.11.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.cabextract.org.uk/cabextract-1.11.tar.gz && \
    tar -xzf cabextract-1.11.tar.gz && \
    mv cabextract-1.11 build && \
    rm cabextract-1.11.tar.gz

WORKDIR /work/build

# 3. Build with WLLVM using autotools
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# 4. Extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc cabextract && \
    mv cabextract.bc /work/bc/

# 5. Verify
RUN ls -la /work/bc/
