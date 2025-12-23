FROM thebesttv/svf:latest

# 1. Install WLLVM
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download expat source code

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: expat" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: https://github.com/libexpat/libexpat/releases/download/R_2_7_3/expat-2.7.3.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libexpat/libexpat/releases/download/R_2_7_3/expat-2.7.3.tar.gz && \
    tar -xzf expat-2.7.3.tar.gz && \
    mv expat-2.7.3 build && \
    rm expat-2.7.3.tar.gz

WORKDIR /work/build

# 3. Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. Configure and build expat with WLLVM (Autotools project)
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --without-docbook

RUN make -j$(nproc)

# 5. Extract bitcode file for xmlwf
RUN mkdir -p /work/bc && \
    extract-bc xmlwf/xmlwf && \
    mv xmlwf/xmlwf.bc /work/bc/

# 6. Verify
RUN ls -la /work/bc/
