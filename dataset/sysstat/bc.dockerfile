FROM thebesttv/svf:latest

# Install wllvm using pip3
RUN apt-get update && \
    apt-get install -y python3-pip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages wllvm

ENV LLVM_COMPILER=clang

# Download and extract sysstat v12.7.6

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: sysstat" > /work/proj && \
    echo "version: 12.7.6" >> /work/proj && \
    echo "source: https://github.com/sysstat/sysstat/archive/v12.7.6.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/sysstat/sysstat/archive/v12.7.6.tar.gz && \
    tar -xzf v12.7.6.tar.gz && \
    mv v12.7.6 build && \
    rm v12.7.6.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file gettext && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-nls

# Build sysstat
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    for bin in sar sadc sadf iostat mpstat pidstat tapestat cifsiostat; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" /work/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la /work/bc/
