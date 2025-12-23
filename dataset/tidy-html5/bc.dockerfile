FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y cmake file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tidy-html5 5.8.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: tidy-html5" > /work/proj && \
    echo "version: 5.8.0" >> /work/proj && \
    echo "source: https://github.com/htacg/tidy-html5/archive/refs/tags/5.8.0.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/htacg/tidy-html5/archive/refs/tags/5.8.0.tar.gz && \
    tar -xzf 5.8.0.tar.gz && \
    mv 5.8.0 build && \
    rm 5.8.0.tar.gz

WORKDIR /work/build

# Build with CMake using WLLVM
RUN rm -rf build && mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIB=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc build/tidy && \
    mv build/tidy.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
