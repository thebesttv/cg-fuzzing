FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract yajl 2.1.0
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/lloyd/yajl/archive/refs/tags/2.1.0.tar.gz && \
    tar -xzf 2.1.0.tar.gz && \
    rm 2.1.0.tar.gz

WORKDIR /home/SVF-tools/yajl-2.1.0

# Install build dependencies (cmake, file for extract-bc)
RUN apt-get update && \
    apt-get install -y cmake file ruby && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with cmake and WLLVM
# Build statically linked binaries
# Link against the static library (yajl_s) instead of shared library
RUN mkdir build && cd build && \
    CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    cmake .. \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF

# Build only the static library and the CLI tools we need
# The tests link against dynamic lib which fails with static linking
RUN cd build && make -j$(nproc) yajl_s json_verify json_reformat

# Create bc directory and extract bitcode files
# json_verify is the main CLI binary for JSON validation
RUN mkdir -p ~/bc && \
    find build -type f -name "json_verify" -executable | while read bin; do \
        extract-bc "$bin" && \
        mv "${bin}.bc" ~/bc/json_verify.bc 2>/dev/null || true; \
    done && \
    find build -type f -name "json_reformat" -executable | while read bin; do \
        extract-bc "$bin" && \
        mv "${bin}.bc" ~/bc/json_reformat.bc 2>/dev/null || true; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
