FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget gettext libpopt-dev uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libexif" > /work/proj && \
    echo "version: libexif-0.6.25 + exif-0.6.22" >> /work/proj && \
    echo "source: https://github.com/libexif/libexif/releases/download/v0.6.25/libexif-0.6.25.tar.gz" >> /work/proj

# Download libexif source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libexif/libexif/releases/download/v0.6.25/libexif-0.6.25.tar.gz && \
    tar -xzf libexif-0.6.25.tar.gz && \
    rm libexif-0.6.25.tar.gz && \
    cp -a libexif-0.6.25 build-libexif-fuzz && \
    cp -a libexif-0.6.25 build-libexif-cmplog && \
    cp -a libexif-0.6.25 build-libexif-cov && \
    cp -a libexif-0.6.25 build-libexif-uftrace && \
    rm -rf libexif-0.6.25

# Download exif CLI source once
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libexif/exif/releases/download/exif-0_6_22-release/exif-0.6.22.tar.gz && \
    tar -xzf exif-0.6.22.tar.gz && \
    rm exif-0.6.22.tar.gz && \
    cp -a exif-0.6.22 build-exif-fuzz && \
    cp -a exif-0.6.22 build-exif-cmplog && \
    cp -a exif-0.6.22 build-exif-cov && \
    cp -a exif-0.6.22 build-exif-uftrace && \
    rm -rf exif-0.6.22

# Build fuzz: libexif + exif CLI with afl-clang-lto
WORKDIR /work/build-libexif-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --prefix=/work/install-fuzz && \
    make -j$(nproc) && \
    make install

WORKDIR /work/build-exif-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -I/work/install-fuzz/include" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -L/work/install-fuzz/lib" \
    PKG_CONFIG_PATH="/work/install-fuzz/lib/pkgconfig" \
    POPT_CFLAGS="-I/usr/include" \
    POPT_LIBS="-lpopt" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-exif-fuzz/exif/exif bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog: libexif + exif CLI with afl-clang-lto + CMPLOG
WORKDIR /work/build-libexif-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared --enable-static --prefix=/work/install-cmplog && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc) && \
    make install

WORKDIR /work/build-exif-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2 -I/work/install-cmplog/include" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -L/work/install-cmplog/lib" \
    PKG_CONFIG_PATH="/work/install-cmplog/lib/pkgconfig" \
    POPT_CFLAGS="-I/usr/include" \
    POPT_LIBS="-lpopt" \
    AFL_LLVM_CMPLOG=1 \
    ./configure --disable-shared && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-exif-cmplog/exif/exif bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY libexif/fuzz/dict /work/dict
COPY libexif/fuzz/in /work/in
COPY libexif/fuzz/fuzz.sh /work/fuzz.sh
COPY libexif/fuzz/whatsup.sh /work/whatsup.sh

# Build cov: libexif + exif CLI with llvm-cov instrumentation
WORKDIR /work/build-libexif-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --prefix=/work/install-cov && \
    make -j$(nproc) && \
    make install

WORKDIR /work/build-exif-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping -I/work/install-cov/include" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition -L/work/install-cov/lib" \
    PKG_CONFIG_PATH="/work/install-cov/lib/pkgconfig" \
    POPT_CFLAGS="-I/usr/include" \
    POPT_LIBS="-lpopt" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-exif-cov/exif/exif bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace: libexif + exif CLI with profiling instrumentation
WORKDIR /work/build-libexif-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --prefix=/work/install-uftrace && \
    make -j$(nproc) && \
    make install

WORKDIR /work/build-exif-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer -I/work/install-uftrace/include" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition -L/work/install-uftrace/lib" \
    PKG_CONFIG_PATH="/work/install-uftrace/lib/pkgconfig" \
    POPT_CFLAGS="-I/usr/include" \
    POPT_LIBS="-lpopt" \
    ./configure --disable-shared && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-exif-uftrace/exif/exif bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
