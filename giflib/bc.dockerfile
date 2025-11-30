FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract giflib 5.2.2
WORKDIR /home/SVF-tools
RUN wget https://sourceforge.net/projects/giflib/files/giflib-5.2.2.tar.gz && \
    tar -xzf giflib-5.2.2.tar.gz && \
    rm giflib-5.2.2.tar.gz

WORKDIR /home/SVF-tools/giflib-5.2.2

# Build with WLLVM for bitcode extraction
# giflib uses a simple Makefile - build only static library and tools
RUN make clean 2>/dev/null || true && \
    make CC=wllvm \
    CFLAGS="-std=gnu99 -Wall -g -O0" \
    libgif.a

# Build the tools statically
RUN make CC=wllvm \
    CFLAGS="-std=gnu99 -Wall -g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    gif2rgb gifbuild giftool giftext gifclrmp giffix

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    for bin in giftext gif2rgb gifbuild giftool gifclrmp giffix; do \
        if [ -f "$bin" ] && [ -x "$bin" ]; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
