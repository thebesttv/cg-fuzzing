FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake flex bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract libcue 2.3.0 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/lipnitsk/libcue/archive/refs/tags/v2.3.0.tar.gz && \
    tar -xzf v2.3.0.tar.gz && \
    rm v2.3.0.tar.gz

WORKDIR /src/libcue-2.3.0

# Build with afl-clang-lto for fuzzing
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && make -j$(nproc)

# Build a simple test harness that parses CUE files
SHELL ["/bin/bash", "-c"]
RUN echo -e '#include <stdio.h>\n#include <stdlib.h>\n#include "libcue.h"\nint main(int argc, char *argv[]) {\n    if (argc < 2) { fprintf(stderr, "Usage: %s <file>\\n", argv[0]); return 1; }\n    FILE *f = fopen(argv[1], "r");\n    if (!f) { perror("fopen"); return 1; }\n    Cd *cd = cue_parse_file(f);\n    fclose(f);\n    if (cd) { cd_delete(cd); printf("OK\\n"); }\n    else { printf("FAIL\\n"); }\n    return 0;\n}' > cue_parse.c
RUN afl-clang-lto -O2 -I. cue_parse.c -Lbuild -lcue \
    -static -Wl,--allow-multiple-definition -o cue_parse

# Install the cue_parse binary
RUN cp cue_parse /out/cue_parse

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf libcue-2.3.0 && \
    wget https://github.com/lipnitsk/libcue/archive/refs/tags/v2.3.0.tar.gz && \
    tar -xzf v2.3.0.tar.gz && \
    rm v2.3.0.tar.gz

WORKDIR /src/libcue-2.3.0

RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
    -DCMAKE_C_FLAGS="-O2" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build the CMPLOG harness
RUN echo -e '#include <stdio.h>\n#include <stdlib.h>\n#include "libcue.h"\nint main(int argc, char *argv[]) {\n    if (argc < 2) { fprintf(stderr, "Usage: %s <file>\\n", argv[0]); return 1; }\n    FILE *f = fopen(argv[1], "r");\n    if (!f) { perror("fopen"); return 1; }\n    Cd *cd = cue_parse_file(f);\n    fclose(f);\n    if (cd) { cd_delete(cd); printf("OK\\n"); }\n    else { printf("FAIL\\n"); }\n    return 0;\n}' > cue_parse.c
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I. cue_parse.c -Lbuild -lcue \
    -static -Wl,--allow-multiple-definition -o cue_parse.cmplog

# Install CMPLOG binary
RUN cp cue_parse.cmplog /out/cue_parse.cmplog

# Copy fuzzing resources
COPY dataset/libcue/fuzz/dict /out/dict
COPY dataset/libcue/fuzz/in /out/in
COPY dataset/libcue/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/libcue/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/cue_parse /out/cue_parse.cmplog && \
    file /out/cue_parse

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing libcue'"]
