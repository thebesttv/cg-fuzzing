FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract cJSON 1.7.19
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.19.tar.gz && \
    tar -xzf v1.7.19.tar.gz && \
    rm v1.7.19.tar.gz

WORKDIR /home/SVF-tools/cJSON-1.7.19

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build using CMake with WLLVM (without fuzzing, just building library)
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_CJSON_TEST=OFF \
    -DENABLE_FUZZING=OFF

RUN cd build && make -j$(nproc)

# Build the afl harness manually
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -I. -Lbuild fuzzing/afl.c -o afl_harness -lcjson \
    -static -Wl,--allow-multiple-definition

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc afl_harness && \
    mv afl_harness.bc ~/bc/cjson_afl.bc

# Verify that bc files were created
RUN ls -la ~/bc/
