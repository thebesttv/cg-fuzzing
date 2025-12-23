FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract nanosvg (master branch, no releases)

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: nanosvg" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: unknown" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/memononen/nanosvg/archive/refs/heads/master.zip && \
    apt-get update && apt-get install -y unzip && \
    unzip master.zip && \
    rm master.zip

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build a simple test harness (nanosvg is header-only)
RUN echo '#define NANOSVG_IMPLEMENTATION' > test_simple.c && \
    echo '#include "src/nanosvg.h"' >> test_simple.c && \
    echo '#include <stdio.h>' >> test_simple.c && \
    echo '#include <string.h>' >> test_simple.c && \
    echo 'int main() {' >> test_simple.c && \
    echo '  const char *svg = "<svg><circle cx=\"10\" cy=\"10\" r=\"5\"/></svg>";' >> test_simple.c && \
    echo '  NSVGimage *image = nsvgParse((char*)svg, "px", 96.0f);' >> test_simple.c && \
    echo '  if (image) {' >> test_simple.c && \
    echo '    printf("Parsed SVG with %d shapes\\n", image->shapes ? 1 : 0);' >> test_simple.c && \
    echo '    nsvgDelete(image);' >> test_simple.c && \
    echo '  }' >> test_simple.c && \
    echo '  return 0;' >> test_simple.c && \
    echo '}' >> test_simple.c

RUN wllvm -g -O0 -Xclang -disable-llvm-passes \
    -I. \
    test_simple.c \
    -static -Wl,--allow-multiple-definition \
    -lm \
    -o test_simple

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc test_simple && \
    mv test_simple.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
