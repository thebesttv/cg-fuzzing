FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract uriparser 0.9.9

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: uriparser" > /work/proj && \
    echo "version: 0.9.9" >> /work/proj && \
    echo "source: https://github.com/uriparser/uriparser/releases/download/uriparser-0.9.9/uriparser-0.9.9.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/uriparser/uriparser/releases/download/uriparser-0.9.9/uriparser-0.9.9.tar.gz && \
    tar -xzf uriparser-0.9.9.tar.gz && \
    mv uriparser-0.9.9 build && \
    rm uriparser-0.9.9.tar.gz

WORKDIR /work/build

# Install build dependencies (cmake, file for extract-bc)
RUN apt-get update && \
    apt-get install -y cmake file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with WLLVM and static linking
RUN mkdir build && cd build && \
    CC=wllvm \
    CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_CXX_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DURIPARSER_BUILD_TESTS=OFF \
        -DURIPARSER_BUILD_DOCS=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc build/uriparse && \
    mv build/uriparse.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
