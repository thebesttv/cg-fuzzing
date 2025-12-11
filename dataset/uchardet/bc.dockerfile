FROM svftools/svf:latest

# 1. Install WLLVM
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download uchardet source code
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.freedesktop.org/software/uchardet/releases/uchardet-0.0.8.tar.xz && \
    tar -xf uchardet-0.0.8.tar.xz && \
    rm uchardet-0.0.8.tar.xz

WORKDIR /home/SVF-tools/uchardet-0.0.8

# 3. Install build dependencies
RUN apt-get update && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. Build uchardet with WLLVM (CMake project)
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_CXX_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_BINARY=ON && \
    make -j$(nproc)

# 5. Extract bitcode file
RUN mkdir -p ~/bc && \
    extract-bc build/src/tools/uchardet && \
    mv build/src/tools/uchardet.bc ~/bc/

# 6. Verify
RUN ls -la ~/bc/
