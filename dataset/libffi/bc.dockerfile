FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libffi v3.4.6
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libffi/libffi/releases/download/v3.4.6/libffi-3.4.6.tar.gz && \
    tar -xzf libffi-3.4.6.tar.gz && \
    rm libffi-3.4.6.tar.gz

WORKDIR /home/SVF-tools/libffi-3.4.6

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file texinfo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static

# Build libffi
RUN make -j$(nproc)

# Build a simple test program to get an executable with bitcode
WORKDIR /home/SVF-tools/libffi-3.4.6
RUN echo '#include <stdio.h>' > test_simple.c && \
    echo '#include <ffi.h>' >> test_simple.c && \
    echo 'void test_func(int a, int b) { printf("Called: %d, %d\\n", a, b); }' >> test_simple.c && \
    echo 'int main() {' >> test_simple.c && \
    echo '  ffi_cif cif;' >> test_simple.c && \
    echo '  ffi_type *args[2];' >> test_simple.c && \
    echo '  void *values[2];' >> test_simple.c && \
    echo '  int a = 42, b = 43;' >> test_simple.c && \
    echo '  args[0] = &ffi_type_sint;' >> test_simple.c && \
    echo '  args[1] = &ffi_type_sint;' >> test_simple.c && \
    echo '  if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, 2, &ffi_type_void, args) == FFI_OK) {' >> test_simple.c && \
    echo '    values[0] = &a;' >> test_simple.c && \
    echo '    values[1] = &b;' >> test_simple.c && \
    echo '    ffi_call(&cif, (void(*)(void))test_func, NULL, values);' >> test_simple.c && \
    echo '  }' >> test_simple.c && \
    echo '  return 0;' >> test_simple.c && \
    echo '}' >> test_simple.c

RUN wllvm -g -O0 -Xclang -disable-llvm-passes \
    -I./include -Ix86_64-pc-linux-gnu/include \
    test_simple.c \
    x86_64-pc-linux-gnu/.libs/libffi.a \
    -static -Wl,--allow-multiple-definition \
    -o test_simple

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc test_simple && \
    mv test_simple.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
