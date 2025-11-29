FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract md4c release-0.5.2
WORKDIR /home/SVF-tools
RUN wget https://github.com/mity/md4c/archive/refs/tags/release-0.5.2.tar.gz && \
    tar -xzf release-0.5.2.tar.gz && \
    rm release-0.5.2.tar.gz

WORKDIR /home/SVF-tools/md4c-release-0.5.2

# Install build dependencies (cmake and file for extract-bc)
RUN apt-get update && \
    apt-get install -y cmake file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build md4c with WLLVM and static linking
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc build/md2html/md2html && \
    mv build/md2html/md2html.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
