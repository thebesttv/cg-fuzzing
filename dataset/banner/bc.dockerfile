FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract banner v1.3.2

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: banner" > /work/proj && \
    echo "version: 1.3.2" >> /work/proj && \
    echo "source: https://shh.thathost.com/pub-unix/files/banner-1.3.2.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://shh.thathost.com/pub-unix/files/banner-1.3.2.tar.gz && \
    tar -xzf banner-1.3.2.tar.gz && \
    mv banner-1.3.2 build && \
    rm banner-1.3.2.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc, shhmsg and shhopt for banner)
RUN apt-get update && \
    apt-get install -y file wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Download and install shhmsg and shhopt dependencies
RUN cd /tmp && \
    wget https://shh.thathost.com/pub-unix/files/shhmsg-1.4.2.tar.gz && \
    tar -xzf shhmsg-1.4.2.tar.gz && \
    cd shhmsg-1.4.2 && \
    make && make INSTBASEDIR=/usr install && \
    cd /tmp && \
    wget https://shh.thathost.com/pub-unix/files/shhopt-1.1.7.tar.gz && \
    tar -xzf shhopt-1.1.7.tar.gz && \
    cd shhopt-1.1.7 && \
    make && make INSTBASEDIR=/usr install

WORKDIR /home/SVF-tools/banner-1.3.2

# Build with WLLVM - override CC in Makefile and use OPTIM for flags
RUN make dep

RUN make CC=wllvm \
    OPTIM="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition"

# Create bc directory and extract bitcode files
RUN mkdir -p /work/bc && \
    extract-bc banner && \
    mv banner.bc /work/bc/

# Verify that bc files were created
RUN ls -la /work/bc/
