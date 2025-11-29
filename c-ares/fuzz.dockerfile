FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract c-ares v1.34.5 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/c-ares/c-ares/releases/download/v1.34.5/c-ares-1.34.5.tar.gz && \
    tar -xzf c-ares-1.34.5.tar.gz && \
    rm c-ares-1.34.5.tar.gz

WORKDIR /src/c-ares-1.34.5

# Build adig with afl-clang-lto for fuzzing (main target binary)
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DCARES_STATIC=ON \
        -DCARES_SHARED=OFF \
        -DCARES_BUILD_TOOLS=ON \
        -DCMAKE_BUILD_TYPE=Release

RUN cd build && make -j$(nproc)

# Install the adig binary
RUN cp build/bin/adig /out/adig

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf c-ares-1.34.5 && \
    wget https://github.com/c-ares/c-ares/releases/download/v1.34.5/c-ares-1.34.5.tar.gz && \
    tar -xzf c-ares-1.34.5.tar.gz && \
    rm c-ares-1.34.5.tar.gz

WORKDIR /src/c-ares-1.34.5

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DCARES_STATIC=ON \
        -DCARES_SHARED=OFF \
        -DCARES_BUILD_TOOLS=ON \
        -DCMAKE_BUILD_TYPE=Release

RUN AFL_LLVM_CMPLOG=1 cd build && make -j$(nproc)

# Install CMPLOG binary
RUN cp build/bin/adig /out/adig.cmplog

# Copy fuzzing resources
COPY c-ares/fuzz/dict /out/dict
COPY c-ares/fuzz/in /out/in
COPY c-ares/fuzz/fuzz.sh /out/fuzz.sh
COPY c-ares/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/adig /out/adig.cmplog && \
    file /out/adig

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing c-ares adig'"]
