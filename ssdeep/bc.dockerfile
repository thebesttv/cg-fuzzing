FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file autoconf automake libtool && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract ssdeep 2.14.1
WORKDIR /home/SVF-tools
RUN wget "https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz" && \
    tar -xzf ssdeep-2.14.1.tar.gz && \
    rm ssdeep-2.14.1.tar.gz

WORKDIR /home/SVF-tools/ssdeep-2.14.1

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0" \
    CXXFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

# Build ssdeep
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc ssdeep && \
    mv ssdeep.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
