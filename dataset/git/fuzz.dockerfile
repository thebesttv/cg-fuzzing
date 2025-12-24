FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libz-dev autoconf uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: git" > /work/proj && \
    echo "version: 2.52.0" >> /work/proj && \
    echo "source: https://github.com/git/git/archive/refs/tags/v2.52.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/git/git/archive/refs/tags/v2.52.0.tar.gz && \
    tar -xzf v2.52.0.tar.gz && \
    rm v2.52.0.tar.gz && \
    cp -a git-2.52.0 build-fuzz && \
    cp -a git-2.52.0 build-cmplog && \
    cp -a git-2.52.0 build-cov && \
    cp -a git-2.52.0 build-uftrace && \
    rm -rf git-2.52.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    NO_OPENSSL=1 \
    NO_CURL=1 \
    NO_EXPAT=1 \
    NO_TCLTK=1 \
    NO_PERL=1 \
    NO_PYTHON=1 \
    NO_GETTEXT=1 \
    NO_ICONV=1 \
    NEEDS_LIBICONV= \
    git

WORKDIR /work
RUN ln -s build-fuzz/git bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    NO_OPENSSL=1 \
    NO_CURL=1 \
    NO_EXPAT=1 \
    NO_TCLTK=1 \
    NO_PERL=1 \
    NO_PYTHON=1 \
    NO_GETTEXT=1 \
    NO_ICONV=1 \
    NEEDS_LIBICONV= \
    git

WORKDIR /work
RUN ln -s build-cmplog/git bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY git/fuzz/dict /work/dict
COPY git/fuzz/in /work/in
COPY git/fuzz/fuzz.sh /work/fuzz.sh
COPY git/fuzz/whatsup.sh /work/whatsup.sh
COPY git/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY git/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY git/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    NO_OPENSSL=1 \
    NO_CURL=1 \
    NO_EXPAT=1 \
    NO_TCLTK=1 \
    NO_PERL=1 \
    NO_PYTHON=1 \
    NO_GETTEXT=1 \
    NO_ICONV=1 \
    NEEDS_LIBICONV= \
    git

WORKDIR /work
RUN ln -s build-cov/git bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN make -j$(nproc) \
    CC=clang \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    NO_OPENSSL=1 \
    NO_CURL=1 \
    NO_EXPAT=1 \
    NO_TCLTK=1 \
    NO_PERL=1 \
    NO_PYTHON=1 \
    NO_GETTEXT=1 \
    NO_ICONV=1 \
    NEEDS_LIBICONV= \
    prefix=/work/install-uftrace \
    git && \
    make install \
    prefix=/work/install-uftrace \
    NO_OPENSSL=1 \
    NO_CURL=1 \
    NO_EXPAT=1 \
    NO_TCLTK=1 \
    NO_PERL=1 \
    NO_PYTHON=1 \
    NO_GETTEXT=1 \
    NO_ICONV=1 \
    NEEDS_LIBICONV=

WORKDIR /work
RUN ln -s install-uftrace/bin/git bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
