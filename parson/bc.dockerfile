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

# Download parson from GitHub (version 1.5.3, latest commit)
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/kgabis/parson/archive/ba29f4eda9ea7703a9f6a9cf2b0532a2605723c3.tar.gz -O parson.tar.gz && \
    tar -xzf parson.tar.gz && \
    rm parson.tar.gz && \
    mv parson-ba29f4eda9ea7703a9f6a9cf2b0532a2605723c3 parson

WORKDIR /home/SVF-tools/parson

# Copy the harness
COPY parson/fuzz/harness.c harness.c

# Build parson library and harness with WLLVM
# Parson is a single-file library, so we compile directly
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -c parson.c -o parson.o

# Build the harness with static linking
RUN wllvm -g -O0 -Xclang -disable-llvm-passes -I. harness.c parson.o -o parson_harness \
    -static -Wl,--allow-multiple-definition

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc parson_harness && \
    mv parson_harness.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
