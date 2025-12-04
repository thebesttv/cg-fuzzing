FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract gperf 3.1
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/gperf/gperf-3.1.tar.gz && \
    tar -xzf gperf-3.1.tar.gz && \
    rm gperf-3.1.tar.gz

WORKDIR /home/SVF-tools/gperf-3.1

# Configure with static linking and WLLVM
# gperf is C++ so we need CXX=wllvm++ 
# -Wno-register to suppress C++17 register keyword error
# Note: Removed -Xclang -disable-llvm-passes from CXXFLAGS as it causes linker errors with C++ std library
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0 -Wno-register" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build gperf
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/gperf && \
    mv src/gperf.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
