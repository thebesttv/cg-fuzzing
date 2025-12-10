FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libcyaml 1.4.2
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 -O libcyaml-1.4.2.tar.gz "https://api.github.com/repos/tlsa/libcyaml/tarball/v1.4.2" && \
    tar -xzf libcyaml-1.4.2.tar.gz && \
    mv tlsa-libcyaml-* libcyaml-1.4.2 && \
    rm libcyaml-1.4.2.tar.gz

WORKDIR /home/SVF-tools/libcyaml-1.4.2

# Install build dependencies (libyaml-dev is required, file for extract-bc)
RUN apt-get update && \
    apt-get install -y file libyaml-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build libcyaml with WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    make -j$(nproc)

# Build numerical example (reads YAML files)
RUN cd examples/numerical && \
    wllvm -g -O0 -Xclang -disable-llvm-passes -I../../include -static -Wl,--allow-multiple-definition \
        -o numerical main.c ../../build/release/libcyaml.a -lyaml

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc examples/numerical/numerical && \
    mv examples/numerical/numerical.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
