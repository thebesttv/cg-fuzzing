FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract lzip v1.15
WORKDIR /home/SVF-tools
RUN wget http://download.savannah.gnu.org/releases/lzip/lzip-1.15.tar.gz && \
    tar -xzf lzip-1.15.tar.gz && \
    rm lzip-1.15.tar.gz

WORKDIR /home/SVF-tools/lzip-1.15

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm CXX=wllvm++ \
    CFLAGS="-g -O0" \
    CXXFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure

# Build lzip - override CXX in make command
RUN make CXX=wllvm++ -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc lzip && \
    mv lzip.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
