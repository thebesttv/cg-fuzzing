FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx xz-utils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download re2c 4.3
WORKDIR /home/SVF-tools
RUN wget https://github.com/skvadrik/re2c/releases/download/4.3/re2c-4.3.tar.xz && \
    tar -xf re2c-4.3.tar.xz && \
    rm re2c-4.3.tar.xz

WORKDIR /home/SVF-tools/re2c-4.3

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure and build re2c with WLLVM
# re2c is a C++ project
RUN CC=wllvm CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc re2c && \
    mv re2c.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
