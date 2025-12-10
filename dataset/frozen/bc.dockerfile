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

# Download and extract frozen 1.7
WORKDIR /home/SVF-tools
RUN wget https://github.com/cesanta/frozen/archive/refs/tags/1.7.tar.gz && \
    tar -xzf 1.7.tar.gz && \
    rm 1.7.tar.gz

WORKDIR /home/SVF-tools/frozen-1.7

# Copy the fuzzing harness
COPY dataset/frozen/fuzz_json.c .

# Compile the fuzzing harness with WLLVM
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -static -Wl,--allow-multiple-definition -o fuzz_json fuzz_json.c frozen.c -lm

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc fuzz_json && \
    mv fuzz_json.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
