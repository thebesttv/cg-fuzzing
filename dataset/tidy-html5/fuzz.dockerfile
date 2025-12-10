FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract tidy-html5 5.8.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/htacg/tidy-html5/archive/refs/tags/5.8.0.tar.gz && \
    tar -xzf 5.8.0.tar.gz && \
    rm 5.8.0.tar.gz

WORKDIR /src/tidy-html5-5.8.0

# Build tidy with afl-clang-lto for fuzzing (main target binary)
RUN rm -rf build && mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIB=OFF

RUN cd build && make -j$(nproc)

# Copy main binary
RUN cp build/tidy /out/tidy

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf tidy-html5-5.8.0 && \
    wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/htacg/tidy-html5/archive/refs/tags/5.8.0.tar.gz && \
    tar -xzf 5.8.0.tar.gz && \
    rm 5.8.0.tar.gz

WORKDIR /src/tidy-html5-5.8.0

RUN rm -rf build && mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIB=OFF

RUN AFL_LLVM_CMPLOG=1 cd build && make -j$(nproc)

# Copy CMPLOG binary
RUN cp build/tidy /out/tidy.cmplog

# Copy fuzzing resources
COPY tidy-html5/fuzz/dict /out/dict
COPY tidy-html5/fuzz/in /out/in
COPY tidy-html5/fuzz/fuzz.sh /out/fuzz.sh
COPY tidy-html5/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/tidy /out/tidy.cmplog && \
    file /out/tidy && \
    /out/tidy --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tidy-html5'"]
