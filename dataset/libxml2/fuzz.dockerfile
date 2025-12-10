FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libxml2 v2.15.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://download.gnome.org/sources/libxml2/2.15/libxml2-2.15.1.tar.xz && \
    tar -xJf libxml2-2.15.1.tar.xz && \
    rm libxml2-2.15.1.tar.xz

WORKDIR /src/libxml2-2.15.1

# Build xmllint with afl-clang-lto for fuzzing (main target binary)
# Use static linking and disable unnecessary features
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DLIBXML2_WITH_PYTHON=OFF \
        -DLIBXML2_WITH_ICU=OFF \
        -DLIBXML2_WITH_LZMA=OFF \
        -DLIBXML2_WITH_ZLIB=OFF

RUN cd build && make -j$(nproc)

# Install the xmllint binary
RUN cp build/xmllint /out/xmllint

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libxml2-2.15.1 && \
    wget https://download.gnome.org/sources/libxml2/2.15/libxml2-2.15.1.tar.xz && \
    tar -xJf libxml2-2.15.1.tar.xz && \
    rm libxml2-2.15.1.tar.xz

WORKDIR /src/libxml2-2.15.1

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DLIBXML2_WITH_PYTHON=OFF \
        -DLIBXML2_WITH_ICU=OFF \
        -DLIBXML2_WITH_LZMA=OFF \
        -DLIBXML2_WITH_ZLIB=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/xmllint /out/xmllint.cmplog

# Copy fuzzing resources
COPY dataset/libxml2/fuzz/dict /out/dict
COPY dataset/libxml2/fuzz/in /out/in
COPY dataset/libxml2/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libxml2/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/xmllint /out/xmllint.cmplog && \
    file /out/xmllint && \
    /out/xmllint --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libxml2'"]
