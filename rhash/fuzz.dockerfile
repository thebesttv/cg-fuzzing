FROM aflplusplus/aflplusplus:latest

# Install build dependencies (including openssl for static linking)
RUN apt-get update && \
    apt-get install -y wget libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract RHash 1.4.5 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/rhash/RHash/archive/refs/tags/v1.4.5.tar.gz && \
    tar -xzf v1.4.5.tar.gz && \
    rm v1.4.5.tar.gz

WORKDIR /src/RHash-1.4.5

# Configure and build RHash with afl-clang-lto for fuzzing
RUN ./configure --cc=afl-clang-lto --extra-cflags="-O2" --extra-ldflags="-static -Wl,--allow-multiple-definition" --disable-lib-shared --enable-static

RUN make -j$(nproc)
RUN cp rhash /out/rhash

# Build CMPLOG version
WORKDIR /src
RUN rm -rf RHash-1.4.5 && \
    wget https://github.com/rhash/RHash/archive/refs/tags/v1.4.5.tar.gz && \
    tar -xzf v1.4.5.tar.gz && \
    rm v1.4.5.tar.gz

WORKDIR /src/RHash-1.4.5

RUN AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-lto --extra-cflags="-O2" --extra-ldflags="-static -Wl,--allow-multiple-definition" --disable-lib-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp rhash /out/rhash.cmplog

# Copy fuzzing resources
COPY rhash/fuzz/dict /out/dict
COPY rhash/fuzz/in /out/in
COPY rhash/fuzz/fuzz.sh /out/fuzz.sh
COPY rhash/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/rhash /out/rhash.cmplog && \
    file /out/rhash && \
    /out/rhash --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing rhash'"]
