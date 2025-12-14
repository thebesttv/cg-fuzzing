FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract monocypher v4.0.2
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://monocypher.org/download/monocypher-4.0.2.tar.gz && \
    tar -xzf monocypher-4.0.2.tar.gz && \
    rm monocypher-4.0.2.tar.gz

WORKDIR /home/SVF-tools/monocypher-4.0.2

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build monocypher library
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -c src/monocypher.c -o monocypher.o && \
    ar rcs libmonocypher.a monocypher.o

# Build a simple test harness
RUN echo '#include "src/monocypher.h"' > test_simple.c && \
    echo '#include <stdio.h>' >> test_simple.c && \
    echo '#include <string.h>' >> test_simple.c && \
    echo 'int main() {' >> test_simple.c && \
    echo '  uint8_t hash[64];' >> test_simple.c && \
    echo '  const uint8_t *message = (const uint8_t*)"Hello World";' >> test_simple.c && \
    echo '  crypto_blake2b(hash, 64, message, 11);' >> test_simple.c && \
    echo '  printf("Hash computed\\n");' >> test_simple.c && \
    echo '  return 0;' >> test_simple.c && \
    echo '}' >> test_simple.c

RUN wllvm -g -O0 -Xclang -disable-llvm-passes \
    -I. \
    test_simple.c \
    libmonocypher.a \
    -static -Wl,--allow-multiple-definition \
    -o test_simple

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc test_simple && \
    mv test_simple.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
