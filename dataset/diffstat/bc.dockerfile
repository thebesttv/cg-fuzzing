FROM svftools/svf:latest

RUN apt-get update && apt-get install -y pipx python3-tomli python3.10-venv && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

WORKDIR /home/SVF-tools
RUN wget https://invisible-island.net/datafiles/release/diffstat.tar.gz && tar -xzf diffstat.tar.gz && rm diffstat.tar.gz

WORKDIR /home/SVF-tools/diffstat-1.68

RUN apt-get update && apt-get install -y file && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN CC=wllvm CFLAGS="-g -O0 -Xclang -disable-llvm-passes" LDFLAGS="-static -Wl,--allow-multiple-definition" ./configure

RUN make -j$(nproc)

RUN mkdir -p ~/bc && extract-bc diffstat && mv diffstat.bc ~/bc/

RUN ls -la ~/bc/
