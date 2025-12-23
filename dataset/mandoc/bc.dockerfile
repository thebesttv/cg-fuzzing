FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract mandoc 1.14.6

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: mandoc" > /work/proj && \
    echo "version: 1.14.6" >> /work/proj && \
    echo "source: https://mandoc.bsd.lv/snapshots/mandoc.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://mandoc.bsd.lv/snapshots/mandoc.tar.gz && \
    tar -xzf mandoc.tar.gz && \
    mv mandoc build && \
    rm mandoc.tar.gz

WORKDIR /work/build

# Configure mandoc with WLLVM
# mandoc uses its own configure script, set CC in configure.local
RUN printf 'CC=wllvm\nCFLAGS="-g -O0 -Xclang -disable-llvm-passes"\nLDFLAGS="-static -Wl,--allow-multiple-definition"\nSTATIC=-static\n' > configure.local

RUN ./configure

# Build mandoc
RUN make mandoc -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc mandoc && \
    mv mandoc.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
