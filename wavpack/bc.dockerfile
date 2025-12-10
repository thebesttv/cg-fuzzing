FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract wavpack v5.8.1
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/dbry/WavPack/archive/refs/tags/5.8.1.tar.gz && \
    tar -xzf 5.8.1.tar.gz && \
    rm 5.8.1.tar.gz

WORKDIR /home/SVF-tools/WavPack-5.8.1

# Install build dependencies (file for extract-bc, cmake for building)
RUN apt-get update && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build wavpack with WLLVM using CMake
RUN mkdir build && cd build && \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_SHARED_LIBS=OFF \
        -DWAVPACK_BUILD_PROGRAMS=ON \
        -DWAVPACK_BUILD_DOCS=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    for bin in build/wavpack build/wvunpack build/wvgain build/wvtag; do \
        if [ -f "$bin" ] && [ -x "$bin" ]; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
