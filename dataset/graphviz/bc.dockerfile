FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract graphviz v12.2.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: graphviz" > /work/proj && \
    echo "version: 12.2.1" >> /work/proj && \
    echo "source: https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/12.2.1/graphviz-12.2.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/12.2.1/graphviz-12.2.1.tar.gz && \
    tar -xzf graphviz-12.2.1.tar.gz && \
    mv graphviz-12.2.1 build && \
    rm graphviz-12.2.1.tar.gz

WORKDIR /work/build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool flex bison \
        libgd-dev libexpat1-dev zlib1g-dev libpng-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Disable plugins and GUI features for simpler static build
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --without-x \
        --without-qt \
        --without-gtk \
        --without-glade \
        --disable-ltdl \
        --enable-ltdl-install=no

# Build graphviz
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from main tools
RUN mkdir -p /work/bc && \
    for tool in cmd/dot/dot_static cmd/gvpr/gvpr cmd/lefty/lefty cmd/tools/acyclic \
                cmd/tools/bcomps cmd/tools/ccomps cmd/tools/dijkstra \
                cmd/tools/gc cmd/tools/gvcolor cmd/tools/gvpack \
                cmd/tools/nop cmd/tools/sccmap cmd/tools/tred cmd/tools/unflatten; do \
        if [ -f "$tool" ] && [ -x "$tool" ]; then \
            extract-bc "$tool" && \
            bcname=$(basename "$tool" | sed 's/_static//').bc && \
            mv "${tool}.bc" /work/bc/"$bcname" 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la /work/bc/
