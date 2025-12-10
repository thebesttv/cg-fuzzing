FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract iniparser v4.2.6 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/ndevilla/iniparser/archive/refs/tags/v4.2.6.tar.gz && \
    tar -xzf v4.2.6.tar.gz && \
    rm v4.2.6.tar.gz

WORKDIR /src/iniparser-4.2.6

# Build with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && make -j$(nproc)

# Build the parse example
RUN afl-clang-lto -O2 -I src \
    -static -Wl,--allow-multiple-definition \
    example/parse.c build/libiniparser.a -o parse

# Install the parse binary
RUN cp parse /out/parse

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf iniparser-4.2.6 && \
    wget https://github.com/ndevilla/iniparser/archive/refs/tags/v4.2.6.tar.gz && \
    tar -xzf v4.2.6.tar.gz && \
    rm v4.2.6.tar.gz

WORKDIR /src/iniparser-4.2.6

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build the CMPLOG parse example
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I src \
    -static -Wl,--allow-multiple-definition \
    example/parse.c build/libiniparser.a -o parse.cmplog

# Install CMPLOG binary
RUN cp parse.cmplog /out/parse.cmplog

# Copy fuzzing resources
COPY dataset/iniparser/fuzz/dict /out/dict
COPY dataset/iniparser/fuzz/in /out/in
COPY dataset/iniparser/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/iniparser/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/parse /out/parse.cmplog && \
    file /out/parse

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing iniparser'"]
