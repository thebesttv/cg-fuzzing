FROM svftools/svf:latest

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
WORKDIR /home/SVF-tools
RUN wget https://github.com/codeplea/tinyexpr/archive/refs/heads/master.tar.gz -O tinyexpr.tar.gz && \
    tar -xzf tinyexpr.tar.gz && \
    rm tinyexpr.tar.gz

WORKDIR /home/SVF-tools/tinyexpr-master

# Build with static linking and WLLVM
# Build repl as the target binary
RUN wllvm -c -g -O0 -Xclang -disable-llvm-passes -Wall tinyexpr.c -o tinyexpr.o && \
    wllvm -c -g -O0 -Xclang -disable-llvm-passes -Wall repl.c -o repl.o && \
    wllvm -g -O0 -Xclang -disable-llvm-passes -static -Wl,--allow-multiple-definition -o repl repl.o tinyexpr.o -lm

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc repl && \
    mv repl.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
