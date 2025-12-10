FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y cmake flex bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libcue 2.3.0
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/lipnitsk/libcue/archive/refs/tags/v2.3.0.tar.gz && \
    tar -xzf v2.3.0.tar.gz && \
    rm v2.3.0.tar.gz

WORKDIR /home/SVF-tools/libcue-2.3.0

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build using CMake with WLLVM
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && make -j$(nproc)

# Build a simple test harness that parses CUE files
SHELL ["/bin/bash", "-c"]
RUN echo -e '#include <stdio.h>\n#include <stdlib.h>\n#include "libcue.h"\nint main(int argc, char *argv[]) {\n    if (argc < 2) { fprintf(stderr, "Usage: %s <file>\\n", argv[0]); return 1; }\n    FILE *f = fopen(argv[1], "r");\n    if (!f) { perror("fopen"); return 1; }\n    Cd *cd = cue_parse_file(f);\n    fclose(f);\n    if (cd) { cd_delete(cd); printf("OK\\n"); }\n    else { printf("FAIL\\n"); }\n    return 0;\n}' > cue_parse.c
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -I. cue_parse.c -Lbuild -lcue \
    -static -Wl,--allow-multiple-definition -o cue_parse

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc cue_parse && \
    mv cue_parse.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
