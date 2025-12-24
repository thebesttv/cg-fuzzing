FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget xz-utils uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: duktape" > /work/proj && \
    echo "version: 2.7.0" >> /work/proj && \
    echo "source: https://github.com/svaarala/duktape/releases/download/v2.7.0/duktape-2.7.0.tar.xz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/svaarala/duktape/releases/download/v2.7.0/duktape-2.7.0.tar.xz && \
    tar -xf duktape-2.7.0.tar.xz && \
    rm duktape-2.7.0.tar.xz && \
    cp -a duktape-2.7.0 build-fuzz && \
    cp -a duktape-2.7.0 build-cmplog && \
    cp -a duktape-2.7.0 build-cov && \
    cp -a duktape-2.7.0 build-uftrace && \
    rm -rf duktape-2.7.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN afl-clang-lto -O2 -std=c99 \
    -I./src \
    -o duk \
    ./src/duktape.c \
    ./examples/cmdline/duk_cmdline.c \
    -lm \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-fuzz/duk bin-fuzz && \
    /work/bin-fuzz -e '1+1'

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -std=c99 \
    -I./src \
    -o duk \
    ./src/duktape.c \
    ./examples/cmdline/duk_cmdline.c \
    -lm \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cmplog/duk bin-cmplog && \
    /work/bin-cmplog -e '1+1'

# Copy fuzzing resources
COPY duktape/fuzz/dict /work/dict
COPY duktape/fuzz/in /work/in
COPY duktape/fuzz/fuzz.sh /work/fuzz.sh
COPY duktape/fuzz/whatsup.sh /work/whatsup.sh
COPY duktape/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY duktape/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY duktape/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN clang -O0 -g -std=c99 \
    -fprofile-instr-generate -fcoverage-mapping \
    -I./src \
    -o duk \
    ./src/duktape.c \
    ./examples/cmdline/duk_cmdline.c \
    -lm \
    -static -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-cov/duk bin-cov && \
    /work/bin-cov -e '1+1' && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN clang -O0 -g -std=c99 \
    -pg -fno-omit-frame-pointer \
    -I./src \
    -o duk \
    ./src/duktape.c \
    ./examples/cmdline/duk_cmdline.c \
    -lm \
    -Wl,--allow-multiple-definition

WORKDIR /work
RUN ln -s build-uftrace/duk bin-uftrace && \
    /work/bin-uftrace -e '1+1' && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
