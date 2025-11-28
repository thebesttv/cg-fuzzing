FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract git v2.52.0
WORKDIR /home/SVF-tools
RUN wget https://github.com/git/git/archive/refs/tags/v2.52.0.tar.gz && \
    tar -xzf v2.52.0.tar.gz && \
    rm v2.52.0.tar.gz

WORKDIR /home/SVF-tools/git-2.52.0

# Install build dependencies
RUN apt-get update && \
    apt-get install -y \
    file \
    libz-dev \
    libcurl4-openssl-dev \
    libexpat1-dev \
    gettext \
    autoconf \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build git with WLLVM
# Git uses a simple Makefile - we disable optional features for simpler static linking
RUN make -j$(nproc) \
    CC=wllvm \
    CFLAGS="-g -O0" \
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

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc git && \
    mv git.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
