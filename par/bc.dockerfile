FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract par v1.53.0
WORKDIR /home/SVF-tools
RUN wget http://www.nicemice.net/par/Par-1.53.0.tar.gz && \
    tar -xzf Par-1.53.0.tar.gz && \
    rm Par-1.53.0.tar.gz

WORKDIR /home/SVF-tools/Par-1.53.0

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build par with WLLVM
# par uses a protoMakefile - we'll build manually
RUN wllvm -c -g -O0 -Xclang -disable-llvm-passes buffer.c && \
    wllvm -c -g -O0 -Xclang -disable-llvm-passes charset.c && \
    wllvm -c -g -O0 -Xclang -disable-llvm-passes errmsg.c && \
    wllvm -c -g -O0 -Xclang -disable-llvm-passes reformat.c && \
    wllvm -c -g -O0 -Xclang -disable-llvm-passes par.c && \
    wllvm -g -O0 -Xclang -disable-llvm-passes -static -Wl,--allow-multiple-definition \
        buffer.o charset.o errmsg.o reformat.o par.o -o par

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc par && \
    mv par.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
