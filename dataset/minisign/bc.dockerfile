FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract minisign 0.11
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/jedisct1/minisign/archive/refs/tags/0.11.tar.gz && \
    tar -xzf 0.11.tar.gz && \
    rm 0.11.tar.gz

WORKDIR /home/SVF-tools/minisign-0.11

# Install build dependencies (file for extract-bc, cmake, libsodium, pkg-config)
RUN apt-get update && \
    apt-get install -y file cmake libsodium-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with CMake, static linking and WLLVM
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DCMAKE_BUILD_TYPE=Debug && \
    make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    cd build/CMakeFiles/minisign.dir/src && \
    for obj in *.c.o; do \
        if [ -f "$obj" ]; then \
            extract-bc "$obj" && \
            mv "${obj}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
