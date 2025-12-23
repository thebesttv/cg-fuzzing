FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract ssdeep 2.14.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: ssdeep" > /work/proj && \
    echo "version: 2.14.1" >> /work/proj && \
    echo "source: https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget "https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz" && \
    tar -xzf ssdeep-2.14.1.tar.gz && \
    mv ssdeep-2.14.1 build && \
    rm ssdeep-2.14.1.tar.gz

WORKDIR /work/build

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build ssdeep
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc ssdeep && \
    mv ssdeep.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
