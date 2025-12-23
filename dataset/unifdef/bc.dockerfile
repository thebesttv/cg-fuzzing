FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract unifdef 2.12

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: unifdef" > /work/proj && \
    echo "version: 2.12" >> /work/proj && \
    echo "source: https://ftp2.osuosl.org/pub/blfs/12.4/u/unifdef-2.12.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp2.osuosl.org/pub/blfs/12.4/u/unifdef-2.12.tar.gz && \
    tar -xzf unifdef-2.12.tar.gz && \
    mv unifdef-2.12 build && \
    rm unifdef-2.12.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build unifdef with static linking and WLLVM
RUN make CC=wllvm CFLAGS="-g -O0 -Xclang -disable-llvm-passes" LDFLAGS="-static -Wl,--allow-multiple-definition"

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc unifdef && \
    mv unifdef.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
