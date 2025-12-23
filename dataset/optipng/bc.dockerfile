FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract optipng 0.7.8

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: optipng" > /work/proj && \
    echo "version: 0.7.8" >> /work/proj && \
    echo "source: https://sourceforge.net/projects/optipng/files/OptiPNG/optipng-0.7.8/optipng-0.7.8.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://sourceforge.net/projects/optipng/files/OptiPNG/optipng-0.7.8/optipng-0.7.8.tar.gz && \
    tar -xzf optipng-0.7.8.tar.gz && \
    mv optipng-0.7.8 build && \
    rm optipng-0.7.8.tar.gz

WORKDIR /work/build

# Configure and build with WLLVM for bitcode extraction
# optipng uses a custom configure script, not autotools
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc src/optipng/optipng && \
    mv src/optipng/optipng.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
