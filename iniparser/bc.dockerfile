FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract iniparser v4.2.6
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://github.com/ndevilla/iniparser/archive/refs/tags/v4.2.6.tar.gz && \
    tar -xzf v4.2.6.tar.gz && \
    rm v4.2.6.tar.gz

WORKDIR /home/SVF-tools/iniparser-4.2.6

# Build using CMake with WLLVM
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
    -DCMAKE_C_FLAGS="-g -O0" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
    -DBUILD_SHARED_LIBS=OFF

RUN cd build && make -j$(nproc)

# Build the parse example manually
RUN wllvm -g -O0 -I src \
    -static -Wl,--allow-multiple-definition \
    example/parse.c build/libiniparser.a -o parse

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc parse && \
    mv parse.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
