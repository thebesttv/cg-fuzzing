FROM svftools/svf:latest

# Install build dependencies and copy compiler-rt profile library
RUN apt-get update && \
    apt-get install -y file libclang-rt-16-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    # Copy profile runtime to where custom clang expects it
    mkdir -p /home/SVF-tools/SVF/llvm-16.0.0.obj/lib/clang/16/lib/linux/ && \
    cp /usr/lib/llvm-16/lib/clang/16/lib/linux/libclang_rt.profile-x86_64.a \
       /home/SVF-tools/SVF/llvm-16.0.0.obj/lib/clang/16/lib/linux/ && \
    cp /usr/lib/llvm-16/lib/clang/16/lib/linux/libclang_rt.profile-i386.a \
       /home/SVF-tools/SVF/llvm-16.0.0.obj/lib/clang/16/lib/linux/

# Download and extract jq v1.8.1 (same version as bc.dockerfile)
WORKDIR /home/SVF-tools
RUN wget https://github.com/jqlang/jq/releases/download/jq-1.8.1/jq-1.8.1.tar.gz && \
    tar -xzf jq-1.8.1.tar.gz && \
    rm jq-1.8.1.tar.gz

WORKDIR /home/SVF-tools/jq-1.8.1

# Build jq with llvm-cov instrumentation
# -fprofile-instr-generate: Generate instrumented code for profiling
# -fcoverage-mapping: Generate coverage mapping data
# Use builtin oniguruma and enable all-static for static linking
RUN CC=clang \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure --with-oniguruma=builtin --disable-shared --enable-all-static

# Build jq
RUN make -j$(nproc)

# Create cov directory and copy binary
RUN mkdir -p ~/cov && \
    cp jq ~/cov/

# Verify binary is built
RUN ls -la ~/cov/jq && \
    file ~/cov/jq && \
    ~/cov/jq --version
