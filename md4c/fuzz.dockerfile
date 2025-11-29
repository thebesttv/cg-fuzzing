FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract md4c release-0.5.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/mity/md4c/archive/refs/tags/release-0.5.2.tar.gz && \
    tar -xzf release-0.5.2.tar.gz && \
    rm release-0.5.2.tar.gz

WORKDIR /src/md4c-release-0.5.2

# Build md4c with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && make -j$(nproc)

# Install the md2html binary
RUN cp build/md2html/md2html /out/md2html

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf md4c-release-0.5.2 && \
    wget https://github.com/mity/md4c/archive/refs/tags/release-0.5.2.tar.gz && \
    tar -xzf release-0.5.2.tar.gz && \
    rm release-0.5.2.tar.gz

WORKDIR /src/md4c-release-0.5.2

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/md2html/md2html /out/md2html.cmplog

# Copy fuzzing resources
COPY md4c/fuzz/dict /out/dict
COPY md4c/fuzz/in /out/in
COPY md4c/fuzz/fuzz.sh /out/fuzz.sh
COPY md4c/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/md2html /out/md2html.cmplog && \
    file /out/md2html

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing md4c'"]
