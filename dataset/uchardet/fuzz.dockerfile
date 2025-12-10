FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract uchardet (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://www.freedesktop.org/software/uchardet/releases/uchardet-0.0.8.tar.xz && \
    tar -xf uchardet-0.0.8.tar.xz && \
    rm uchardet-0.0.8.tar.xz

WORKDIR /src/uchardet-0.0.8

# Build uchardet with afl-clang-lto for fuzzing (main target binary)
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_BINARY=ON && \
    make -j$(nproc)

# Copy the uchardet binary
RUN cp build/src/tools/uchardet /out/uchardet

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf uchardet-0.0.8 && \
    wget https://www.freedesktop.org/software/uchardet/releases/uchardet-0.0.8.tar.xz && \
    tar -xf uchardet-0.0.8.tar.xz && \
    rm uchardet-0.0.8.tar.xz

WORKDIR /src/uchardet-0.0.8

RUN mkdir build && cd build && \
    AFL_LLVM_CMPLOG=1 CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_BINARY=ON && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp build/src/tools/uchardet /out/uchardet.cmplog

# Copy fuzzing resources
COPY dataset/uchardet/fuzz/dict /out/dict
COPY dataset/uchardet/fuzz/in /out/in
COPY dataset/uchardet/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/uchardet/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/uchardet /out/uchardet.cmplog && \
    file /out/uchardet && \
    /out/uchardet --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing uchardet'"]
