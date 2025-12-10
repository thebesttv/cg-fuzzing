FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool bison flex && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract gettext v0.23.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://ftp.gnu.org/gnu/gettext/gettext-0.23.1.tar.gz && \
    tar -xzf gettext-0.23.1.tar.gz && \
    rm gettext-0.23.1.tar.gz

WORKDIR /src/gettext-0.23.1

# Build msgfmt with afl-clang-lto for fuzzing (main target binary)
# Use static linking and disable shared libs
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-java --disable-native-java --without-emacs

RUN make -j$(nproc)

# Install the msgfmt binary
RUN cp gettext-tools/src/msgfmt /out/msgfmt

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf gettext-0.23.1 && \
    wget https://ftp.gnu.org/gnu/gettext/gettext-0.23.1.tar.gz && \
    tar -xzf gettext-0.23.1.tar.gz && \
    rm gettext-0.23.1.tar.gz

WORKDIR /src/gettext-0.23.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --disable-java --disable-native-java --without-emacs

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp gettext-tools/src/msgfmt /out/msgfmt.cmplog

# Copy fuzzing resources
COPY dataset/gettext/fuzz/dict /out/dict
COPY dataset/gettext/fuzz/in /out/in
COPY dataset/gettext/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/gettext/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/msgfmt /out/msgfmt.cmplog && \
    file /out/msgfmt && \
    /out/msgfmt --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing msgfmt'"]
