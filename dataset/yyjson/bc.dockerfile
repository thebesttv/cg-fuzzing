FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract yyjson v0.12.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/ibireme/yyjson/archive/refs/tags/0.12.0.tar.gz && \
    tar -xzf 0.12.0.tar.gz && \
    rm 0.12.0.tar.gz

WORKDIR /home/SVF-tools/yyjson-0.12.0

# Build using CMake with WLLVM
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DYYJSON_BUILD_TESTS=OFF

RUN cd build && make -j$(nproc)

# Copy the harness
COPY yyjson/harness.c harness.c

# Build the harness
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -I src \
    -static -Wl,--allow-multiple-definition \
    harness.c build/libyyjson.a -o yyjson_parse

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc yyjson_parse && \
    mv yyjson_parse.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
