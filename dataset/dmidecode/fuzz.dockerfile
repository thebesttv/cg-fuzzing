FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: dmidecode" > /work/proj && \
    echo "version: 3.6" >> /work/proj && \
    echo "source: https://download.savannah.gnu.org/releases/dmidecode/dmidecode-3.6.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.savannah.gnu.org/releases/dmidecode/dmidecode-3.6.tar.xz && \
    tar -xJf dmidecode-3.6.tar.xz && \
    rm dmidecode-3.6.tar.xz && \
    cp -a dmidecode-3.6 build-fuzz && \
    cp -a dmidecode-3.6 build-cmplog && \
    cp -a dmidecode-3.6 build-cov && \
    cp -a dmidecode-3.6 build-uftrace && \
    rm -rf dmidecode-3.6

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/dmidecode bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/dmidecode bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY dmidecode/fuzz/dict /work/dict
COPY dmidecode/fuzz/in /work/in
COPY dmidecode/fuzz/fuzz.sh /work/fuzz.sh
COPY dmidecode/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/dmidecode bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/dmidecode bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
