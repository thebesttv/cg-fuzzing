FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract msgpack-c v6.1.0
WORKDIR /home/SVF-tools
RUN wget -O msgpack-c-6.1.0.tar.gz https://github.com/msgpack/msgpack-c/archive/refs/tags/c-6.1.0.tar.gz && \
    tar -xzf msgpack-c-6.1.0.tar.gz && \
    rm msgpack-c-6.1.0.tar.gz

WORKDIR /home/SVF-tools/msgpack-c-c-6.1.0

# Install build dependencies (file for extract-bc, cmake for building)
RUN apt-get update && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM using CMake
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_CXX_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DMSGPACK_BUILD_TESTS=OFF \
        -DMSGPACK_BUILD_EXAMPLES=ON

# Build msgpack-c
WORKDIR /home/SVF-tools/msgpack-c-c-6.1.0/build
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from examples
RUN mkdir -p ~/bc && \
    for bin in example/*; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
