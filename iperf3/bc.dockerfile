FROM svftools/svf:latest

# Install wllvm using pip3
RUN apt-get update && \
    apt-get install -y python3-pip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages wllvm

ENV LLVM_COMPILER=clang

# Download and extract iperf3 v3.17.1
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/esnet/iperf/releases/download/3.17.1/iperf-3.17.1.tar.gz && \
    tar -xzf iperf-3.17.1.tar.gz && \
    rm iperf-3.17.1.tar.gz

WORKDIR /home/SVF-tools/iperf-3.17.1

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

# Build iperf3
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    for bin in src/iperf3; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
