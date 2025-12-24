FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake flex bison uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libcue" > /work/proj && \
    echo "version: 2.3.0" >> /work/proj && \
    echo "source: https://github.com/lipnitsk/libcue/archive/refs/tags/v2.3.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/lipnitsk/libcue/archive/refs/tags/v2.3.0.tar.gz && \
    tar -xzf v2.3.0.tar.gz && \
    rm v2.3.0.tar.gz && \
    cp -a libcue-2.3.0 build-fuzz && \
    cp -a libcue-2.3.0 build-cmplog && \
    cp -a libcue-2.3.0 build-cov && \
    cp -a libcue-2.3.0 build-uftrace && \
    rm -rf libcue-2.3.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc)

# Build harness for fuzz
SHELL ["/bin/bash", "-c"]
RUN echo -e '#include <stdio.h>\n#include <stdlib.h>\n#include "libcue.h"\nint main(int argc, char *argv[]) {\n    if (argc < 2) { fprintf(stderr, "Usage: %s <file>\\n", argv[0]); return 1; }\n    FILE *f = fopen(argv[1], "r");\n    if (!f) { perror("fopen"); return 1; }\n    Cd *cd = cue_parse_file(f);\n    fclose(f);\n    if (cd) { cd_delete(cd); printf("OK\\n"); }\n    else { printf("FAIL\\n"); }\n    return 0;\n}' > cue_parse.c && \
    afl-clang-lto -O2 -I. cue_parse.c -Lbuild -lcue \
        -static -Wl,--allow-multiple-definition -o cue_parse

WORKDIR /work
RUN ln -s build-fuzz/cue_parse bin-fuzz && \
    /work/bin-fuzz 2>&1 | head -1

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir build && cd build && \
    CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Build harness for cmplog
RUN echo -e '#include <stdio.h>\n#include <stdlib.h>\n#include "libcue.h"\nint main(int argc, char *argv[]) {\n    if (argc < 2) { fprintf(stderr, "Usage: %s <file>\\n", argv[0]); return 1; }\n    FILE *f = fopen(argv[1], "r");\n    if (!f) { perror("fopen"); return 1; }\n    Cd *cd = cue_parse_file(f);\n    fclose(f);\n    if (cd) { cd_delete(cd); printf("OK\\n"); }\n    else { printf("FAIL\\n"); }\n    return 0;\n}' > cue_parse.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto -O2 -I. cue_parse.c -Lbuild -lcue \
        -static -Wl,--allow-multiple-definition -o cue_parse

WORKDIR /work
RUN ln -s build-cmplog/cue_parse bin-cmplog && \
    /work/bin-cmplog 2>&1 | head -1

# Copy fuzzing resources
COPY libcue/fuzz/dict /work/dict
COPY libcue/fuzz/in /work/in
COPY libcue/fuzz/fuzz.sh /work/fuzz.sh
COPY libcue/fuzz/whatsup.sh /work/whatsup.sh
COPY libcue/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libcue/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libcue/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc)

# Build harness for cov
RUN echo -e '#include <stdio.h>\n#include <stdlib.h>\n#include "libcue.h"\nint main(int argc, char *argv[]) {\n    if (argc < 2) { fprintf(stderr, "Usage: %s <file>\\n", argv[0]); return 1; }\n    FILE *f = fopen(argv[1], "r");\n    if (!f) { perror("fopen"); return 1; }\n    Cd *cd = cue_parse_file(f);\n    fclose(f);\n    if (cd) { cd_delete(cd); printf("OK\\n"); }\n    else { printf("FAIL\\n"); }\n    return 0;\n}' > cue_parse.c && \
    clang -g -O0 -fprofile-instr-generate -fcoverage-mapping -I. cue_parse.c -Lbuild -lcue \
        -static -Wl,--allow-multiple-definition -o cue_parse

WORKDIR /work
RUN ln -s build-cov/cue_parse bin-cov && \
    /work/bin-cov 2>&1 | head -1 && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir build && cd build && \
    CC=clang \
    CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc)

# Build harness for uftrace
RUN echo -e '#include <stdio.h>\n#include <stdlib.h>\n#include "libcue.h"\nint main(int argc, char *argv[]) {\n    if (argc < 2) { fprintf(stderr, "Usage: %s <file>\\n", argv[0]); return 1; }\n    FILE *f = fopen(argv[1], "r");\n    if (!f) { perror("fopen"); return 1; }\n    Cd *cd = cue_parse_file(f);\n    fclose(f);\n    if (cd) { cd_delete(cd); printf("OK\\n"); }\n    else { printf("FAIL\\n"); }\n    return 0;\n}' > cue_parse.c && \
    clang -g -O0 -pg -fno-omit-frame-pointer -I. cue_parse.c -Lbuild -lcue \
        -pg -Wl,--allow-multiple-definition -o cue_parse

WORKDIR /work
RUN ln -s build-uftrace/cue_parse bin-uftrace && \
    /work/bin-uftrace 2>&1 | head -1 && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
