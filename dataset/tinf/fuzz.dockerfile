FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract tinf (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/jibsen/tinf/archive/refs/tags/v1.2.1.tar.gz && \
    tar -xzf v1.2.1.tar.gz && \
    rm v1.2.1.tar.gz

WORKDIR /src/tinf-1.2.1

# Build tinf with afl-clang-lto for fuzzing (main target binary)
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc)

# Copy the tgunzip binary
RUN cp build/tgunzip /out/tgunzip

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf tinf-1.2.1 && \
    wget https://github.com/jibsen/tinf/archive/refs/tags/v1.2.1.tar.gz && \
    tar -xzf v1.2.1.tar.gz && \
    rm v1.2.1.tar.gz

WORKDIR /src/tinf-1.2.1

RUN mkdir build && cd build && \
    AFL_LLVM_CMPLOG=1 CC=afl-clang-lto \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp build/tgunzip /out/tgunzip.cmplog

# Copy fuzzing resources
COPY dataset/tinf/fuzz/dict /out/dict
COPY dataset/tinf/fuzz/in /out/in
COPY dataset/tinf/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/tinf/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/tgunzip /out/tgunzip.cmplog && \
    file /out/tgunzip

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing tinf'"]
