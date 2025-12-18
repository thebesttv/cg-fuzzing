FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract snappy v1.2.1
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/google/snappy/archive/refs/tags/1.2.1.tar.gz && \
    tar -xzf 1.2.1.tar.gz && \
    rm 1.2.1.tar.gz

WORKDIR /home/SVF-tools/snappy-1.2.1

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file cmake ninja-build && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM (CMake project)
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_CXX_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        -DSNAPPY_BUILD_TESTS=OFF \
        -DSNAPPY_BUILD_BENCHMARKS=OFF

# Build snappy
RUN cd build && make -j$(nproc)

# Build a simple test harness
WORKDIR /home/SVF-tools/snappy-1.2.1
RUN echo '#include <snappy.h>' > test_simple.cc && \
    echo '#include <string>' >> test_simple.cc && \
    echo '#include <stdio.h>' >> test_simple.cc && \
    echo 'int main() {' >> test_simple.cc && \
    echo '  std::string input = "Hello World";' >> test_simple.cc && \
    echo '  std::string compressed;' >> test_simple.cc && \
    echo '  std::string uncompressed;' >> test_simple.cc && \
    echo '  snappy::Compress(input.data(), input.size(), &compressed);' >> test_simple.cc && \
    echo '  snappy::Uncompress(compressed.data(), compressed.size(), &uncompressed);' >> test_simple.cc && \
    echo '  printf("Compressed: %zu -> %zu\\n", input.size(), compressed.size());' >> test_simple.cc && \
    echo '  return 0;' >> test_simple.cc && \
    echo '}' >> test_simple.cc

RUN wllvm++ -g -O0 -Xclang -disable-llvm-passes \
    -I. -Ibuild \
    test_simple.cc \
    build/libsnappy.a \
    -static -Wl,--allow-multiple-definition \
    -o test_simple

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc test_simple && \
    mv test_simple.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
