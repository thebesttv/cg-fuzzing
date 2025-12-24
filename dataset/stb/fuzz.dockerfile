FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget git uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: stb" > /work/proj && \
    echo "version: latest" >> /work/proj && \
    echo "source: https://github.com/nothings/stb.git" >> /work/proj

# Download source once and clone to multiple build directories
RUN git clone --depth 1 https://github.com/nothings/stb.git && \
    cp -a stb build-fuzz && \
    cp -a stb build-cmplog && \
    cp -a stb build-cov && \
    cp -a stb build-uftrace && \
    rm -rf stb

# Create harness helper function to avoid repetition
RUN echo '/* stb_image harness for fuzzing/analysis */' > /tmp/harness_template.c && \
    echo '#define STB_IMAGE_IMPLEMENTATION' >> /tmp/harness_template.c && \
    echo '#include "stb_image.h"' >> /tmp/harness_template.c && \
    echo '#include <stdio.h>' >> /tmp/harness_template.c && \
    echo '#include <stdlib.h>' >> /tmp/harness_template.c && \
    echo 'int main(int argc, char **argv) {' >> /tmp/harness_template.c && \
    echo '    if (argc != 2) { fprintf(stderr, "Usage: %s <image_file>\\n", argv[0]); return 1; }' >> /tmp/harness_template.c && \
    echo '    int width, height, channels;' >> /tmp/harness_template.c && \
    echo '    unsigned char *data = stbi_load(argv[1], &width, &height, &channels, 0);' >> /tmp/harness_template.c && \
    echo '    if (data == NULL) { fprintf(stderr, "Failed to load image: %s\\n", stbi_failure_reason()); return 1; }' >> /tmp/harness_template.c && \
    echo '    printf("Loaded image: %dx%d, %d channels\\n", width, height, channels);' >> /tmp/harness_template.c && \
    echo '    stbi_image_free(data);' >> /tmp/harness_template.c && \
    echo '    return 0;' >> /tmp/harness_template.c && \
    echo '}' >> /tmp/harness_template.c

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN cp /tmp/harness_template.c stb_image_harness.c && \
    afl-clang-lto \
    -O2 \
    -static \
    -Wl,--allow-multiple-definition \
    -o stb_image_harness stb_image_harness.c \
    -lm

WORKDIR /work
RUN ln -s build-fuzz/stb_image_harness bin-fuzz && \
    /work/bin-fuzz 2>&1 | grep -q "Usage" && echo "bin-fuzz OK"

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN cp /tmp/harness_template.c stb_image_harness.c && \
    AFL_LLVM_CMPLOG=1 afl-clang-lto \
    -O2 \
    -static \
    -Wl,--allow-multiple-definition \
    -o stb_image_harness stb_image_harness.c \
    -lm

WORKDIR /work
RUN ln -s build-cmplog/stb_image_harness bin-cmplog && \
    /work/bin-cmplog 2>&1 | grep -q "Usage" && echo "bin-cmplog OK"

# Copy fuzzing resources
COPY stb/fuzz/dict /work/dict
COPY stb/fuzz/in /work/in
COPY stb/fuzz/fuzz.sh /work/fuzz.sh
COPY stb/fuzz/whatsup.sh /work/whatsup.sh
COPY stb/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY stb/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY stb/fuzz/collect-branch.py /work/collect-branch.py

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN cp /tmp/harness_template.c stb_image_harness.c && \
    clang \
    -g -O0 -fprofile-instr-generate -fcoverage-mapping \
    -static -Wl,--allow-multiple-definition \
    -o stb_image_harness stb_image_harness.c \
    -lm

WORKDIR /work
RUN ln -s build-cov/stb_image_harness bin-cov && \
    /work/bin-cov 2>&1 | grep -q "Usage" && echo "bin-cov OK" && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN cp /tmp/harness_template.c stb_image_harness.c && \
    clang \
    -g -O0 -pg -fno-omit-frame-pointer \
    -Wl,--allow-multiple-definition \
    -o stb_image_harness stb_image_harness.c \
    -lm

WORKDIR /work
RUN ln -s build-uftrace/stb_image_harness bin-uftrace && \
    /work/bin-uftrace 2>&1 | grep -q "Usage" && echo "bin-uftrace OK" && \
    rm -f gmon.out

# Clean up template
RUN rm -f /tmp/harness_template.c

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
