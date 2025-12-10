FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake nasm && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libjpeg-turbo 3.1.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/3.1.2.tar.gz && \
    tar -xzf 3.1.2.tar.gz && \
    rm 3.1.2.tar.gz

WORKDIR /src/libjpeg-turbo-3.1.2

# Build djpeg with afl-clang-lto for fuzzing (main target binary)
# Use static linking and disable TurboJPEG
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DENABLE_SHARED=OFF \
        -DENABLE_STATIC=ON \
        -DWITH_TURBOJPEG=OFF

RUN cd build && make -j$(nproc)

# Install the djpeg binary
RUN cp build/djpeg-static /out/djpeg

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libjpeg-turbo-3.1.2 && \
    wget https://github.com/libjpeg-turbo/libjpeg-turbo/archive/refs/tags/3.1.2.tar.gz && \
    tar -xzf 3.1.2.tar.gz && \
    rm 3.1.2.tar.gz

WORKDIR /src/libjpeg-turbo-3.1.2

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DENABLE_SHARED=OFF \
        -DENABLE_STATIC=ON \
        -DWITH_TURBOJPEG=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp build/djpeg-static /out/djpeg.cmplog

# Copy fuzzing resources
COPY dataset/libjpeg-turbo/fuzz/dict /out/dict
COPY dataset/libjpeg-turbo/fuzz/in /out/in
COPY dataset/libjpeg-turbo/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libjpeg-turbo/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/djpeg /out/djpeg.cmplog && \
    file /out/djpeg

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libjpeg-turbo'"]
