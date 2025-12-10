FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract uriparser 0.9.9 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/uriparser/uriparser/releases/download/uriparser-0.9.9/uriparser-0.9.9.tar.gz && \
    tar -xzf uriparser-0.9.9.tar.gz && \
    rm uriparser-0.9.9.tar.gz

WORKDIR /src/uriparser-0.9.9

# Build uriparse with afl-clang-lto for fuzzing (main target binary)
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DURIPARSER_BUILD_TESTS=OFF \
        -DURIPARSER_BUILD_DOCS=OFF

RUN cd build && make -j$(nproc)

# Install the uriparse binary
RUN cp build/uriparse /out/uriparse

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf uriparser-0.9.9 && \
    wget https://github.com/uriparser/uriparser/releases/download/uriparser-0.9.9/uriparser-0.9.9.tar.gz && \
    tar -xzf uriparser-0.9.9.tar.gz && \
    rm uriparser-0.9.9.tar.gz

WORKDIR /src/uriparser-0.9.9

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DURIPARSER_BUILD_TESTS=OFF \
        -DURIPARSER_BUILD_DOCS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/uriparse /out/uriparse.cmplog

# Copy fuzzing resources
COPY uriparser/fuzz/dict /out/dict
COPY uriparser/fuzz/in /out/in
COPY uriparser/fuzz/fuzz.sh /out/fuzz.sh
COPY uriparser/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/uriparse /out/uriparse.cmplog && \
    file /out/uriparse && \
    /out/uriparse --help || true

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing uriparser'"]
