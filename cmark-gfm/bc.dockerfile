FROM svftools/svf:latest

# 1. Install WLLVM
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y cmake file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download cmark-gfm source code (v0.29.0.gfm.13)
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/github/cmark-gfm/archive/refs/tags/0.29.0.gfm.13.tar.gz && \
    tar -xzf 0.29.0.gfm.13.tar.gz && \
    rm 0.29.0.gfm.13.tar.gz

WORKDIR /home/SVF-tools/cmark-gfm-0.29.0.gfm.13

# 3. Build with WLLVM using CMake
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DCMARK_STATIC=ON \
        -DCMARK_SHARED=OFF \
        -DCMARK_TESTS=OFF

RUN cd build && make -j$(nproc)

# 4. Extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc build/src/cmark-gfm && \
    mv build/src/cmark-gfm.bc ~/bc/

# 5. Verify
RUN ls -la ~/bc/
