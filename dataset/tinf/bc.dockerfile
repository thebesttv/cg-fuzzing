FROM thebesttv/svf:latest

# 1. Install WLLVM
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download tinf source code

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: tinf" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: https://github.com/jibsen/tinf/archive/refs/tags/v1.2.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jibsen/tinf/archive/refs/tags/v1.2.1.tar.gz && \
    tar -xzf v1.2.1.tar.gz && \
    mv v1.2.1 build && \
    rm v1.2.1.tar.gz

WORKDIR /work/build

# 3. Install build dependencies
RUN apt-get update && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. Build tinf with WLLVM using CMake
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc)

# 5. Extract bitcode file for tgunzip
RUN mkdir -p /work/bc && \
    find build -name "tgunzip" -type f -executable && \
    extract-bc build/tgunzip && \
    mv build/tgunzip.bc /work/bc/

# 6. Verify
RUN ls -la /work/bc/
