FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download stb (latest commit - same as bc.dockerfile)
WORKDIR /src
RUN git clone --depth 1 https://github.com/nothings/stb.git

WORKDIR /src/stb

# Create a harness program that uses stb_image to load images
RUN echo '/* stb_image harness for fuzzing/analysis */' > stb_image_harness.c && \
    echo '#define STB_IMAGE_IMPLEMENTATION' >> stb_image_harness.c && \
    echo '#include "stb_image.h"' >> stb_image_harness.c && \
    echo '#include <stdio.h>' >> stb_image_harness.c && \
    echo '#include <stdlib.h>' >> stb_image_harness.c && \
    echo 'int main(int argc, char **argv) {' >> stb_image_harness.c && \
    echo '    if (argc != 2) { fprintf(stderr, "Usage: %s <image_file>\\n", argv[0]); return 1; }' >> stb_image_harness.c && \
    echo '    int width, height, channels;' >> stb_image_harness.c && \
    echo '    unsigned char *data = stbi_load(argv[1], &width, &height, &channels, 0);' >> stb_image_harness.c && \
    echo '    if (data == NULL) { fprintf(stderr, "Failed to load image: %s\\n", stbi_failure_reason()); return 1; }' >> stb_image_harness.c && \
    echo '    printf("Loaded image: %dx%d, %d channels\\n", width, height, channels);' >> stb_image_harness.c && \
    echo '    stbi_image_free(data);' >> stb_image_harness.c && \
    echo '    return 0;' >> stb_image_harness.c && \
    echo '}' >> stb_image_harness.c

# Build the harness with afl-clang-lto and static linking
RUN afl-clang-lto \
    -O2 \
    -static \
    -Wl,--allow-multiple-definition \
    -o stb_image_harness stb_image_harness.c \
    -lm

RUN cp stb_image_harness /out/stb_image_harness

# Build CMPLOG version for better fuzzing
WORKDIR /src
RUN rm -rf stb && \
    git clone --depth 1 https://github.com/nothings/stb.git

WORKDIR /src/stb

# Create the harness again
RUN echo '/* stb_image harness for fuzzing/analysis */' > stb_image_harness.c && \
    echo '#define STB_IMAGE_IMPLEMENTATION' >> stb_image_harness.c && \
    echo '#include "stb_image.h"' >> stb_image_harness.c && \
    echo '#include <stdio.h>' >> stb_image_harness.c && \
    echo '#include <stdlib.h>' >> stb_image_harness.c && \
    echo 'int main(int argc, char **argv) {' >> stb_image_harness.c && \
    echo '    if (argc != 2) { fprintf(stderr, "Usage: %s <image_file>\\n", argv[0]); return 1; }' >> stb_image_harness.c && \
    echo '    int width, height, channels;' >> stb_image_harness.c && \
    echo '    unsigned char *data = stbi_load(argv[1], &width, &height, &channels, 0);' >> stb_image_harness.c && \
    echo '    if (data == NULL) { fprintf(stderr, "Failed to load image: %s\\n", stbi_failure_reason()); return 1; }' >> stb_image_harness.c && \
    echo '    printf("Loaded image: %dx%d, %d channels\\n", width, height, channels);' >> stb_image_harness.c && \
    echo '    stbi_image_free(data);' >> stb_image_harness.c && \
    echo '    return 0;' >> stb_image_harness.c && \
    echo '}' >> stb_image_harness.c

# Build CMPLOG version
RUN AFL_LLVM_CMPLOG=1 afl-clang-lto \
    -O2 \
    -static \
    -Wl,--allow-multiple-definition \
    -o stb_image_harness stb_image_harness.c \
    -lm

RUN cp stb_image_harness /out/stb_image_harness.cmplog

# Copy fuzzing resources
COPY stb/fuzz/dict /out/dict
COPY stb/fuzz/in /out/in
COPY stb/fuzz/fuzz.sh /out/fuzz.sh
COPY stb/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/stb_image_harness /out/stb_image_harness.cmplog && \
    file /out/stb_image_harness

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing stb_image'"]
