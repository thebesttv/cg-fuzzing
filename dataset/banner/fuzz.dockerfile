FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Download and install shhmsg and shhopt dependencies
RUN cd /tmp && \
    wget https://shh.thathost.com/pub-unix/files/shhmsg-1.4.2.tar.gz && \
    tar -xzf shhmsg-1.4.2.tar.gz && \
    cd shhmsg-1.4.2 && \
    make && make INSTBASEDIR=/usr install && \
    cd /tmp && \
    wget https://shh.thathost.com/pub-unix/files/shhopt-1.1.7.tar.gz && \
    tar -xzf shhopt-1.1.7.tar.gz && \
    cd shhopt-1.1.7 && \
    make && make INSTBASEDIR=/usr install

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: banner" > /work/proj && \
    echo "version: 1.3.2" >> /work/proj && \
    echo "source: https://shh.thathost.com/pub-unix/files/banner-1.3.2.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://shh.thathost.com/pub-unix/files/banner-1.3.2.tar.gz && \
    tar -xzf banner-1.3.2.tar.gz && \
    rm banner-1.3.2.tar.gz && \
    cp -a banner-1.3.2 build-fuzz && \
    cp -a banner-1.3.2 build-cmplog && \
    cp -a banner-1.3.2 build-cov && \
    cp -a banner-1.3.2 build-uftrace && \
    rm -rf banner-1.3.2

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make dep

RUN make CC=afl-clang-lto \
    OPTIM="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/banner bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN make dep

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    OPTIM="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/banner bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY banner/fuzz/dict /work/dict
COPY banner/fuzz/in /work/in
COPY banner/fuzz/fuzz.sh /work/fuzz.sh
COPY banner/fuzz/whatsup.sh /work/whatsup.sh
COPY banner/fuzz/1-run-cov.sh /work/1-run-cov.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make dep

RUN make CC=clang \
    OPTIM="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/banner bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make dep

RUN make CC=clang \
    OPTIM="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-uftrace/banner bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
