FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract json-c 0.18
WORKDIR /home/SVF-tools
RUN wget https://github.com/json-c/json-c/archive/refs/tags/json-c-0.18-20240915.tar.gz && \
    tar -xzf json-c-0.18-20240915.tar.gz && \
    rm json-c-0.18-20240915.tar.gz

WORKDIR /home/SVF-tools/json-c-json-c-0.18-20240915

# Install build dependencies (cmake and file for extract-bc)
RUN apt-get update && \
    apt-get install -y cmake file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build json-c with WLLVM and static linking
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_APPS=ON

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc build/apps/json_parse && \
    mv build/apps/json_parse.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
