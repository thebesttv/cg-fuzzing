FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libxml2 v2.15.1
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://download.gnome.org/sources/libxml2/2.15/libxml2-2.15.1.tar.xz && \
    tar -xJf libxml2-2.15.1.tar.xz && \
    rm libxml2-2.15.1.tar.xz

WORKDIR /home/SVF-tools/libxml2-2.15.1

# Install build dependencies (file for extract-bc, cmake for build)
RUN apt-get update && \
    apt-get install -y file cmake pkg-config liblzma-dev zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with CMake and WLLVM
# Disable Python bindings and shared library, enable static linking
RUN mkdir build && cd build && \
    CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DLIBXML2_WITH_PYTHON=OFF \
        -DLIBXML2_WITH_ICU=OFF \
        -DLIBXML2_WITH_LZMA=OFF \
        -DLIBXML2_WITH_ZLIB=OFF

# Build libxml2
RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc build/xmllint && \
    mv build/xmllint.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
