FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget autoconf automake libtool bison flex uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: gettext" > /work/proj && \
    echo "version: 0.23.1" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/gettext/gettext-0.23.1.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/gettext/gettext-0.23.1.tar.gz && \
    tar -xzf gettext-0.23.1.tar.gz && \
    rm gettext-0.23.1.tar.gz && \
    cp -a gettext-0.23.1 build-fuzz && \
    cp -a gettext-0.23.1 build-cmplog && \
    cp -a gettext-0.23.1 build-cov && \
    cp -a gettext-0.23.1 build-uftrace && \
    rm -rf gettext-0.23.1

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-java --disable-native-java --without-emacs && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/gettext-tools/src/msgfmt bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    CXXFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --disable-java --disable-native-java --without-emacs && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/gettext-tools/src/msgfmt bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY gettext/fuzz/dict /work/dict
COPY gettext/fuzz/in /work/in
COPY gettext/fuzz/fuzz.sh /work/fuzz.sh
COPY gettext/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    CXXFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-java --disable-native-java --without-emacs && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/gettext-tools/src/msgfmt bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    CXXFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-java --disable-native-java --without-emacs --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/msgfmt bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
