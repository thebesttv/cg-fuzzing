FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract mpack 1.1.1 (amalgamation version)
WORKDIR /home/SVF-tools
RUN wget https://github.com/ludocode/mpack/releases/download/v1.1.1/mpack-amalgamation-1.1.1.tar.gz && \
    tar -xzf mpack-amalgamation-1.1.1.tar.gz && \
    rm mpack-amalgamation-1.1.1.tar.gz

WORKDIR /home/SVF-tools/mpack-amalgamation-1.1.1

# Copy the fuzzing harness
COPY mpack/fuzz_mpack.c .

# Compile the fuzzing harness with WLLVM and mpack library
# mpack is a single-file library, we can compile it directly
RUN wllvm -g -O0 -DMPACK_READER=1 -DMPACK_EXTENSIONS=1 \
    -static -Wl,--allow-multiple-definition \
    -o fuzz_mpack fuzz_mpack.c src/mpack/mpack.c -lm

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc fuzz_mpack && \
    mv fuzz_mpack.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
