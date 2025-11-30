FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract WavPack 5.8.1
WORKDIR /home/SVF-tools
RUN wget https://github.com/dbry/WavPack/releases/download/5.8.1/wavpack-5.8.1.tar.xz && \
    tar -xf wavpack-5.8.1.tar.xz && \
    rm wavpack-5.8.1.tar.xz

WORKDIR /home/SVF-tools/wavpack-5.8.1

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build wavpack
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from CLI tools
RUN mkdir -p ~/bc && \
    for bin in cli/wavpack cli/wvunpack cli/wvgain cli/wvtag; do \
        if [ -f "$bin" ]; then \
            extract-bc "$bin" && \
            name=$(basename "$bin") && \
            mv "${bin}.bc" ~/bc/${name}.bc 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
