FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract dos2unix 7.5.2

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: dos2unix" > /work/proj && \
    echo "version: 7.5.2" >> /work/proj && \
    echo "source: https://downloads.sourceforge.net/project/dos2unix/dos2unix/7.5.2/dos2unix-7.5.2.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget "https://downloads.sourceforge.net/project/dos2unix/dos2unix/7.5.2/dos2unix-7.5.2.tar.gz" && \
    tar -xzf dos2unix-7.5.2.tar.gz && \
    mv dos2unix-7.5.2 build && \
    rm dos2unix-7.5.2.tar.gz

WORKDIR /work/build

# Build with static linking and WLLVM
RUN make CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ENABLE_NLS=

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc dos2unix && \
    mv dos2unix.bc /work/bc/ && \
    extract-bc unix2dos && \
    mv unix2dos.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
