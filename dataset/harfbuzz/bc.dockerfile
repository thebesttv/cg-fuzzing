FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract harfbuzz v10.1.0

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: harfbuzz" > /work/proj && \
    echo "version: 10.1.0" >> /work/proj && \
    echo "source: https://github.com/harfbuzz/harfbuzz/releases/download/10.1.0/harfbuzz-10.1.0.tar.xz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/harfbuzz/harfbuzz/releases/download/10.1.0/harfbuzz-10.1.0.tar.xz && \
    tar -xf harfbuzz-10.1.0.tar.xz && \
    mv harfbuzz-10.1.0 build && \
    rm harfbuzz-10.1.0.tar.xz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file meson ninja-build pkg-config libfreetype6-dev libglib2.0-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM (Meson project)
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    meson setup .. \
        --default-library=static \
        --prefix=/home/SVF-tools/harfbuzz-10.1.0/install \
        -Dtests=disabled \
        -Dutilities=disabled \
        -Ddocs=disabled \
        -Dfreetype=disabled \
        -Dglib=disabled

# Build harfbuzz
RUN cd build && ninja

# Build a simple test harness
WORKDIR /home/SVF-tools/harfbuzz-10.1.0
RUN echo '#include <hb.h>' > test_simple.c && \
    echo '#include <stdio.h>' >> test_simple.c && \
    echo 'int main() {' >> test_simple.c && \
    echo '  hb_buffer_t *buf = hb_buffer_create();' >> test_simple.c && \
    echo '  const char *text = "Hello";' >> test_simple.c && \
    echo '  hb_buffer_add_utf8(buf, text, -1, 0, -1);' >> test_simple.c && \
    echo '  hb_buffer_guess_segment_properties(buf);' >> test_simple.c && \
    echo '  hb_font_t *font = hb_font_create(hb_face_create(hb_blob_get_empty(), 0));' >> test_simple.c && \
    echo '  hb_shape(font, buf, NULL, 0);' >> test_simple.c && \
    echo '  unsigned int glyph_count;' >> test_simple.c && \
    echo '  hb_glyph_info_t *glyph_info = hb_buffer_get_glyph_infos(buf, &glyph_count);' >> test_simple.c && \
    echo '  printf("Shaped %u glyphs\\n", glyph_count);' >> test_simple.c && \
    echo '  hb_font_destroy(font);' >> test_simple.c && \
    echo '  hb_buffer_destroy(buf);' >> test_simple.c && \
    echo '  return 0;' >> test_simple.c && \
    echo '}' >> test_simple.c

RUN wllvm -g -O0 -Xclang -disable-llvm-passes \
    -Isrc \
    test_simple.c \
    build/src/libharfbuzz.a \
    -static -Wl,--allow-multiple-definition \
    -lm \
    -o test_simple

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc test_simple && \
    mv test_simple.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
