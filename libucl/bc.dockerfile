FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libucl 0.9.2
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/vstakhov/libucl/archive/refs/tags/0.9.2.tar.gz && \
    tar -xzf 0.9.2.tar.gz && \
    rm 0.9.2.tar.gz

WORKDIR /home/SVF-tools/libucl-0.9.2

# Install build dependencies (cmake and file for extract-bc)
RUN apt-get update && \
    apt-get install -y cmake file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build libucl with WLLVM and static linking
# Enable ENABLE_UTILS to build ucl-tool
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF \
    -DENABLE_UTILS=ON

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc build/utils/ucl_tool && \
    mv build/utils/ucl_tool.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
