FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract par v1.53.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: par" > /work/proj && \
    echo "version: 1.53.0" >> /work/proj && \
    echo "source: http://www.nicemice.net/par/Par-1.53.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 http://www.nicemice.net/par/Par-1.53.0.tar.gz && \
    tar -xzf Par-1.53.0.tar.gz && \
    mv Par-1.53.0 build && \
    rm Par-1.53.0.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build par with WLLVM
# par uses a protoMakefile - we'll build manually
RUN wllvm -c -g -O0 -Xclang -disable-llvm-passes buffer.c && \
    wllvm -c -g -O0 -Xclang -disable-llvm-passes charset.c && \
    wllvm -c -g -O0 -Xclang -disable-llvm-passes errmsg.c && \
    wllvm -c -g -O0 -Xclang -disable-llvm-passes reformat.c && \
    wllvm -c -g -O0 -Xclang -disable-llvm-passes par.c && \
    wllvm -g -O0 -Xclang -disable-llvm-passes -static -Wl,--allow-multiple-definition \
        buffer.o charset.o errmsg.o reformat.o par.o -o par

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc par && \
    mv par.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
