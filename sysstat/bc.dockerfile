FROM svftools/svf:latest

# Install wllvm using pip3
RUN apt-get update && \
    apt-get install -y python3-pip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages wllvm

ENV LLVM_COMPILER=clang

# Download and extract sysstat v12.7.6
WORKDIR /home/SVF-tools
RUN wget https://github.com/sysstat/sysstat/archive/v12.7.6.tar.gz && \
    tar -xzf v12.7.6.tar.gz && \
    rm v12.7.6.tar.gz

WORKDIR /home/SVF-tools/sysstat-12.7.6

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
RUN mkdir -p ~/bc && \
    for bin in sar sadc sadf iostat mpstat pidstat tapestat cifsiostat; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
