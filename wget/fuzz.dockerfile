FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libssl-dev pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract wget --tries=3 --retry-connrefused --waitretry=5 v1.24.5 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/wget/wget-1.24.5.tar.gz && \
    tar -xzf wget-1.24.5.tar.gz && \
    rm wget-1.24.5.tar.gz

WORKDIR /src/wget-1.24.5

# Build wget --tries=3 --retry-connrefused --waitretry=5 with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --with-ssl=openssl --disable-nls

RUN make -j$(nproc)

# Install the wget --tries=3 --retry-connrefused --waitretry=5 binary
RUN cp src/wget --tries=3 --retry-connrefused --waitretry=5 /out/wget
--tries=3 --retry-connrefused --waitretry=5 
# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf wget-1.24.5 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/wget/wget-1.24.5.tar.gz && \
    tar -xzf wget-1.24.5.tar.gz && \
    rm wget-1.24.5.tar.gz

WORKDIR /src/wget-1.24.5

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --with-ssl=openssl --disable-nls

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/wget --tries=3 --retry-connrefused --waitretry=5 /out/wget.cmplog

# Copy fuzzing resources
COPY wget/fuzz/dict /out/dict
COPY wget/fuzz/in /out/in
COPY wget/fuzz/fuzz.sh /out/fuzz.sh
COPY wget/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/wget --tries=3 --retry-connrefused --waitretry=5 /out/wget.cmplog && \
    file /out/wget --tries=3 --retry-connrefused --waitretry=5 && \
    /out/wget --tries=3 --retry-connrefused --waitretry=5 --version | head -5

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing wget'"]
