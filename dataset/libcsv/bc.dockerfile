FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libcsv 3.0.3
WORKDIR /home/SVF-tools
RUN wget -O libcsv-3.0.3.tar.gz "https://sourceforge.net/projects/libcsv/files/libcsv/libcsv-3.0.3/libcsv-3.0.3.tar.gz/download" && \
    tar -xzf libcsv-3.0.3.tar.gz && \
    rm libcsv-3.0.3.tar.gz

WORKDIR /home/SVF-tools/libcsv-3.0.3

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build libcsv
RUN make -j$(nproc)

# Also build example tools
# Fix include path: examples use "libcsv/csv.h" but header is at ../csv.h
RUN mkdir -p libcsv && cp csv.h libcsv/csv.h && \
    cd examples && \
    for f in *.c; do \
        name=$(basename $f .c); \
        wllvm -g -O0 -Xclang -disable-llvm-passes -I.. -static -Wl,--allow-multiple-definition -o $name $f ../.libs/libcsv.a; \
    done

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc examples/csvinfo && \
    mv examples/csvinfo.bc ~/bc/ && \
    extract-bc examples/csvvalid && \
    mv examples/csvvalid.bc ~/bc/ && \
    extract-bc examples/csvfix && \
    mv examples/csvfix.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
