FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool flex bison \
        libgd-dev libexpat1-dev zlib1g-dev libpng-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract graphviz v12.2.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/12.2.1/graphviz-12.2.1.tar.gz && \
    tar -xzf graphviz-12.2.1.tar.gz && \
    rm graphviz-12.2.1.tar.gz

WORKDIR /src/graphviz-12.2.1

# Build graphviz with afl-clang-lto for fuzzing (main target binary)
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --without-x \
        --without-qt \
        --without-gtk \
        --without-glade \
        --disable-ltdl \
        --enable-ltdl-install=no

RUN make -j$(nproc)

# Install the dot binary (main tool for graph rendering)
RUN cp cmd/dot/dot_static /out/dot

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf graphviz-12.2.1 && \
    wget https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/12.2.1/graphviz-12.2.1.tar.gz && \
    tar -xzf graphviz-12.2.1.tar.gz && \
    rm graphviz-12.2.1.tar.gz

WORKDIR /src/graphviz-12.2.1

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --without-x \
        --without-qt \
        --without-gtk \
        --without-glade \
        --disable-ltdl \
        --enable-ltdl-install=no

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Install CMPLOG binary
RUN cp cmd/dot/dot_static /out/dot.cmplog

# Copy fuzzing resources
COPY graphviz/fuzz/dict /out/dict
COPY graphviz/fuzz/in /out/in
COPY graphviz/fuzz/fuzz.sh /out/fuzz.sh
COPY graphviz/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/dot /out/dot.cmplog && \
    file /out/dot && \
    /out/dot -V

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing graphviz dot'"]
