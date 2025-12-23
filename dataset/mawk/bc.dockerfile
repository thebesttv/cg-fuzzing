FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract mawk 1.3.4-20240905

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: mawk" > /work/proj && \
    echo "version: 1.3.4-20240905" >> /work/proj && \
    echo "source: https://invisible-mirror.net/archives/mawk/mawk-1.3.4-20240905.tgz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://invisible-mirror.net/archives/mawk/mawk-1.3.4-20240905.tgz && \
    tar -xzf mawk-1.3.4-20240905.tgz && \
    mv mawk-1.3.4-20240905 build && \
    rm mawk-1.3.4-20240905.tgz

WORKDIR /work/build

# Configure mawk with WLLVM and static linking
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build mawk
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc mawk && \
    mv mawk.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
