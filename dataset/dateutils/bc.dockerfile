FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file xz-utils autoconf automake libtool flex bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract dateutils v0.4.11

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: dateutils" > /work/proj && \
    echo "version: 0.4.11" >> /work/proj && \
    echo "source: https://github.com/hroptatyr/dateutils/releases/download/v0.4.11/dateutils-0.4.11.tar.xz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/hroptatyr/dateutils/releases/download/v0.4.11/dateutils-0.4.11.tar.xz && \
    tar -xJf dateutils-0.4.11.tar.xz && \
    mv dateutils-0.4.11 build && \
    rm dateutils-0.4.11.tar.xz

WORKDIR /work/build

# Build dateutils with WLLVM (autotools project)
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    for bin in src/dadd src/dconv src/ddiff src/dgrep src/dround \
               src/dseq src/dsort src/dtest src/dzone src/strptime; do \
        if [ -f "$bin" ] && [ -x "$bin" ]; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" /work/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la /work/bc/
