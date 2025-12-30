FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget cmake uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: libtiff" > /work/proj && \
    echo "version: 4.7.0" >> /work/proj && \
    echo "source: https://download.osgeo.org/libtiff/tiff-4.7.0.tar.gz" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://download.osgeo.org/libtiff/tiff-4.7.0.tar.gz && \
    tar -xzf tiff-4.7.0.tar.gz && \
    rm tiff-4.7.0.tar.gz && \
    cp -a tiff-4.7.0 build-fuzz && \
    cp -a tiff-4.7.0 build-cmplog && \
    cp -a tiff-4.7.0 build-cov && \
    cp -a tiff-4.7.0 build-uftrace && \
    rm -rf tiff-4.7.0

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir cmake_build && cd cmake_build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DBUILD_SHARED_LIBS=OFF \
        -Dtiff-docs=OFF \
        -Dtiff-tests=OFF \
        -Djpeg=OFF \
        -Djbig=OFF \
        -Dlerc=OFF \
        -Dlzma=OFF \
        -Dzstd=OFF \
        -Dwebp=OFF \
        -Dzlib=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/cmake_build/tools/tiffinfo bin-fuzz && \
    /work/bin-fuzz --version || true

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN mkdir cmake_build && cd cmake_build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    AFL_LLVM_CMPLOG=1 \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_CXX_FLAGS="-O2" \
        -DBUILD_SHARED_LIBS=OFF \
        -Dtiff-docs=OFF \
        -Dtiff-tests=OFF \
        -Djpeg=OFF \
        -Djbig=OFF \
        -Dlerc=OFF \
        -Dlzma=OFF \
        -Dzstd=OFF \
        -Dwebp=OFF \
        -Dzlib=OFF && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/cmake_build/tools/tiffinfo bin-cmplog && \
    /work/bin-cmplog --version || true

# Copy fuzzing resources
COPY libtiff/fuzz/dict /work/dict
COPY libtiff/fuzz/in /work/in
COPY libtiff/fuzz/fuzz.sh /work/fuzz.sh
COPY libtiff/fuzz/whatsup.sh /work/whatsup.sh
COPY libtiff/fuzz/1-run-cov.sh /work/1-run-cov.sh
COPY libtiff/fuzz/2-gen-branch.sh /work/2-gen-branch.sh
COPY libtiff/fuzz/collect-branch.py /work/collect-branch.py
COPY libtiff/fuzz/3-gen-uftrace.sh /work/3-gen-uftrace.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN mkdir cmake_build && cd cmake_build && \
    CC=clang CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_CXX_FLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
        -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
        -DBUILD_SHARED_LIBS=OFF \
        -Dtiff-docs=OFF \
        -Dtiff-tests=OFF \
        -Djpeg=OFF \
        -Djbig=OFF \
        -Dlerc=OFF \
        -Dlzma=OFF \
        -Dzstd=OFF \
        -Dwebp=OFF \
        -Dzlib=OFF && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/cmake_build/tools/tiffinfo bin-cov && \
    /work/bin-cov --version || true && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN mkdir cmake_build && cd cmake_build && \
    CC=clang CXX=clang++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_CXX_FLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-pg" \
        -DCMAKE_INSTALL_PREFIX=/work/install-uftrace \
        -DBUILD_SHARED_LIBS=OFF \
        -Dtiff-docs=OFF \
        -Dtiff-tests=OFF \
        -Djpeg=OFF \
        -Djbig=OFF \
        -Dlerc=OFF \
        -Dlzma=OFF \
        -Dzstd=OFF \
        -Dwebp=OFF \
        -Dzlib=OFF && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/tiffinfo bin-uftrace && \
    /work/bin-uftrace --version || true && \
    uftrace record /work/bin-uftrace --version || true && \
    uftrace report && \
    rm -rf uftrace.data gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
