FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract iniparser v4.2.6

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: iniparser" > /work/proj && \
    echo "version: 4.2.6" >> /work/proj && \
    echo "source: https://github.com/ndevilla/iniparser/archive/refs/tags/v4.2.6.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/ndevilla/iniparser/archive/refs/tags/v4.2.6.tar.gz && \
    tar -xzf v4.2.6.tar.gz && \
    mv v4.2.6 build && \
    rm v4.2.6.tar.gz

WORKDIR /work/build

# Build using CMake with WLLVM
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && make -j$(nproc)

# Build the parse example manually
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -I src \
    -static -Wl,--allow-multiple-definition \
    example/parse.c build/libiniparser.a -o parse

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc parse && \
    mv parse.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
