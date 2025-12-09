FROM svftools/svf:latest

# 1. Install WLLVM
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download tinf source code
WORKDIR /home/SVF-tools
RUN wget https://github.com/jibsen/tinf/archive/refs/tags/v1.2.1.tar.gz && \
    tar -xzf v1.2.1.tar.gz && \
    rm v1.2.1.tar.gz

WORKDIR /home/SVF-tools/tinf-1.2.1

# 3. Install build dependencies
RUN apt-get update && \
    apt-get install -y file cmake && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. Build tinf with WLLVM using CMake
RUN mkdir build && cd build && \
    CC=wllvm \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF && \
    make -j$(nproc)

# 5. Extract bitcode file for tgunzip
RUN mkdir -p ~/bc && \
    find build -name "tgunzip" -type f -executable && \
    extract-bc build/tgunzip && \
    mv build/tgunzip.bc ~/bc/

# 6. Verify
RUN ls -la ~/bc/
