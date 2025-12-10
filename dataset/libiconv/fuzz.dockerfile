FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libiconv 1.18 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://ftp.gnu.org/gnu/libiconv/libiconv-1.18.tar.gz && \
    tar -xzf libiconv-1.18.tar.gz && \
    rm libiconv-1.18.tar.gz

WORKDIR /src/libiconv-1.18

# Build libiconv with afl-clang-lto for fuzzing (main target binary)
# Use static linking
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)

# Install the iconv binary
RUN cp src/iconv_no_i18n /out/iconv

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf libiconv-1.18 && \
    wget https://ftp.gnu.org/gnu/libiconv/libiconv-1.18.tar.gz && \
    tar -xzf libiconv-1.18.tar.gz && \
    rm libiconv-1.18.tar.gz

WORKDIR /src/libiconv-1.18

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp src/iconv_no_i18n /out/iconv.cmplog

# Copy fuzzing resources
COPY libiconv/fuzz/dict /out/dict
COPY libiconv/fuzz/in /out/in
COPY libiconv/fuzz/fuzz.sh /out/fuzz.sh
COPY libiconv/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/iconv /out/iconv.cmplog && \
    file /out/iconv && \
    /out/iconv --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libiconv'"]
