FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download stb (latest commit)
WORKDIR /home/SVF-tools
RUN apt-get update && \
    apt-get install -y file git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/nothings/stb.git

WORKDIR /home/SVF-tools/stb

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

# Build the harness with WLLVM and static linking
RUN wllvm \
    -g -O0 -Xclang -disable-llvm-passes \
    -static \
    -Wl,--allow-multiple-definition \
    -o stb_image_harness stb_image_harness.c \
    -lm

# Create bc directory and extract bitcode file
RUN mkdir -p ~/bc && \
    extract-bc stb_image_harness && \
    mv stb_image_harness.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
