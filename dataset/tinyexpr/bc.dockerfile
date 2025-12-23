FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract tinyexpr (latest master)

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: tinyexpr" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: https://github.com/codeplea/tinyexpr/archive/refs/heads/master.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/codeplea/tinyexpr/archive/refs/heads/master.tar.gz -O tinyexpr.tar.gz && \
    tar -xzf tinyexpr.tar.gz && \
    mv tinyexpr build && \
    rm tinyexpr.tar.gz

WORKDIR /work/build

# Build with static linking and WLLVM
# Build repl as the target binary
RUN wllvm -c -g -O0 -Xclang -disable-llvm-passes -Wall tinyexpr.c -o tinyexpr.o && \
    wllvm -c -g -O0 -Xclang -disable-llvm-passes -Wall repl.c -o repl.o && \
    wllvm -g -O0 -Xclang -disable-llvm-passes -static -Wl,--allow-multiple-definition -o repl repl.o tinyexpr.o -lm

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc repl && \
    mv repl.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
