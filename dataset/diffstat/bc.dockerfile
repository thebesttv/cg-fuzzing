FROM thebesttv/svf:latest

RUN apt-get update && apt-get install -y pipx python3-tomli python3.10-venv && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: diffstat" > /work/proj && \
    echo "version: unknown" >> /work/proj && \
    echo "source: https://invisible-island.net/datafiles/release/diffstat.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://invisible-island.net/datafiles/release/diffstat.tar.gz && tar -xzf diffstat.tar.gz && rm diffstat.tar.gz

WORKDIR /work/build

RUN apt-get update && apt-get install -y file && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN CC=wllvm CFLAGS="-g -O0 -Xclang -disable-llvm-passes" LDFLAGS="-static -Wl,--allow-multiple-definition" ./configure

RUN make -j$(nproc)

RUN mkdir -p /work/bc && extract-bc diffstat && mv diffstat.bc /work/bc/

RUN ls -la /work/bc/
