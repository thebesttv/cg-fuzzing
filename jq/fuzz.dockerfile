FROM aflplusplus/aflplusplus:latest

# Download and extract jq v1.8.1 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz && \
    tar -xzf jq-1.8.1.tar.gz && \
    rm jq-1.8.1.tar.gz

WORKDIR /src/jq-1.8.1

# Configure once for all builds
# - afl-clang-lto: LTO mode to avoid hash collisions in coverage
# - Static linking for performance
# - No sanitizers for speed (focus on coverage, not crash detection)
RUN CC=afl-clang-lto \
    CFLAGS="-O2 -flto" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static

# Build main fuzzing binary (without CMPLOG for faster execution)
RUN make -j$(nproc) && cp jq /src/jq.fuzz

# Build CMPLOG binary (requires AFL_LLVM_CMPLOG=1, same config)
RUN make clean && AFL_LLVM_CMPLOG=1 make -j$(nproc) && cp jq /src/jq.cmplog

# Create fuzzing directories
RUN mkdir -p /fuzz/in /fuzz/out

# Download dictionary from oss-fuzz (existing, well-maintained)
RUN wget -O /fuzz/jq.dict https://raw.githubusercontent.com/google/oss-fuzz/master/projects/jq/jq.dict

# Create initial seed corpus with minimal JSON inputs
# These are basic valid JSON values that exercise different parsing paths
RUN echo '{}' > /fuzz/in/empty_object.json && \
    echo '[]' > /fuzz/in/empty_array.json && \
    echo 'null' > /fuzz/in/null.json && \
    echo 'true' > /fuzz/in/true.json && \
    echo '0' > /fuzz/in/zero.json && \
    echo '"a"' > /fuzz/in/string.json && \
    echo '{"k":1}' > /fuzz/in/object.json && \
    echo '[1,2]' > /fuzz/in/array.json

# Create the fuzzing script
COPY <<'SCRIPT' /fuzz/fuzz.sh
#!/bin/bash
set -e

FUZZ_BIN="/src/jq.fuzz"
CMPLOG_BIN="/src/jq.cmplog"
IN_DIR="/fuzz/in"
OUT_DIR="/fuzz/out"
DICT="/fuzz/jq.dict"
FILTER="."

echo "=== jq Fuzzing ==="
echo "Binary: $FUZZ_BIN"
echo "CMPLOG: $CMPLOG_BIN"
echo "Filter: $FILTER"

# Single-core fuzzing with CMPLOG
AFL_AUTORESUME=1 afl-fuzz \
    -i "$IN_DIR" \
    -o "$OUT_DIR" \
    -x "$DICT" \
    -c "$CMPLOG_BIN" \
    -t 1000 \
    -m none \
    -- "$FUZZ_BIN" "$FILTER"
SCRIPT

RUN chmod +x /fuzz/fuzz.sh

WORKDIR /fuzz
CMD ["/fuzz/fuzz.sh"]
