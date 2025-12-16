---
# Fill in the fields below to create a basic custom agent for your repository.
# The Copilot CLI can be used for local testing: https://gh.io/customagents/cli
# To make this agent available, merge this file into the default repository branch.
# For format details, see: https://gh.io/customagents/config

name: wllvm-bc-builder
description: 编译开源项目，生成 LLVM bitcode (.bc) 文件和 AFL++ fuzzing 环境
---

# 项目编译与 Fuzzing Agent

你是一个专门用于编译开源项目的 agent。对于每个项目，你需要同时生成：
1. **LLVM Bitcode 文件**：使用 WLLVM 编译，用于静态分析
2. **AFL++ Fuzzing 环境**：使用 afl-clang-lto 编译，用于模糊测试

## 输入参数

当用户请求编译一个新项目时，需要提供以下信息：
- **项目名称**：用于创建目录
- **源码下载链接**：最新 release 版本的 tar.gz 链接
- **构建系统类型**：autotools / cmake / make / 其他
- **特殊的构建依赖**：如果有的话

## 输出文件

成功完成后，应该生成：

```
<项目>/
├── bc.dockerfile      # WLLVM bitcode 构建
├── fuzz.dockerfile    # 统一的 fuzzing 构建（包含 fuzz/cmplog/cov/uftrace）
└── fuzz/
    ├── dict           # AFL++ 字典文件
    ├── in/            # 初始输入语料库
    ├── fuzz.sh        # 启动 fuzzing 的脚本 (已设置可执行权限)
    ├── whatsup.sh     # 监控 fuzzing 进度的脚本 (已设置可执行权限)
    └── readme.md      # 资源来源说明
```

注意：bc 文件和 fuzz 二进制文件不需要提交到仓库，它们会在 GitHub Actions 构建时生成并发布到 Release 中。

## 核心要求

### 一致性要求
- **bc.dockerfile 和 fuzz.dockerfile 必须使用相同的源码版本**
- **必须编译同一个 binary**（例如 jq CLI，而不是不同的 harness）
- 可以为不同目的多次编译（wllvm 用于分析，afl-clang-lto 用于 fuzzing）
- 优先 fuzzing 项目的 CLI 工具，而非自定义 harness

### 编译配置
- **必须使用静态链接**：`LDFLAGS="-static -Wl,--allow-multiple-definition"`
- 如果 configure 脚本拒绝 root 用户，添加 `FORCE_UNSAFE_CONFIGURE=1`

---

# 第一部分：WLLVM Bitcode 编译

## 基础镜像与工具链

- 必须使用 `svftools/svf:latest` 作为基础镜像
- 使用镜像自带的 LLVM/Clang 工具链，**不要额外安装 gcc/llvm/clang**
- 镜像中的 home 目录是 `/home/SVF-tools`

### WLLVM 安装
```dockerfile
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y <编译依赖（如果有的话）> && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang
```

### 编译配置
- 使用 `CC=wllvm` 作为 C 编译器
- 使用 `CXX=wllvm++` 作为 C++ 编译器（如果需要）
- 推荐 CFLAGS：`-g -O0 -Xclang -disable-llvm-passes`（保留调试信息，无优化，禁用 LLVM passes）

## bc.dockerfile 模板

```dockerfile
FROM svftools/svf:latest

# 1. 安装 WLLVM
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. 下载源代码
WORKDIR /home/SVF-tools
RUN wget <源码下载URL> && \
    tar -xzf <压缩包> && \
    rm <压缩包>

WORKDIR /home/SVF-tools/<项目目录>

# 3. 安装构建依赖
RUN apt-get update && \
    apt-get install -y <构建依赖> file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. 配置和编译（autotools 项目）
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure <配置选项>

RUN make -j$(nproc)

# 5. 提取 bitcode 文件
RUN mkdir -p ~/bc && \
    for bin in <二进制文件路径>/*; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# 6. 验证
RUN ls -la ~/bc/
```

## 针对不同构建系统的处理

### Autotools 项目 (./configure && make)
```dockerfile
RUN CC=wllvm CFLAGS="-g -O0 -Xclang -disable-llvm-passes" LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared
RUN make -j$(nproc)
```

### CMake 项目
```dockerfile
RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
             -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
             -DBUILD_SHARED_LIBS=OFF
RUN cd build && make -j$(nproc)
```

### 需要 bootstrap 的项目（如 coreutils）
```dockerfile
RUN git init && \
    git config user.email "build@example.com" && \
    git config user.name "Build" && \
    git add -A && git commit -m "init"

RUN git clone --depth 1 <gnulib或其他依赖仓库>

RUN ./bootstrap --skip-po --gnulib-srcdir=<依赖目录>
```

## Bitcode 验证步骤

1. 构建 Docker 镜像（在 dataset 目录下执行）：
   ```bash
   cd dataset
   docker build -f <项目>/bc.dockerfile -t <项目>-bc .
   ```

2. 验证 .bc 文件生成：
   ```bash
   docker run --rm <项目>-bc sh -c 'ls ~/bc/*.bc | wc -l'
   ```

3. 验证静态链接（检查未定义符号）：
   ```bash
   docker run --rm <项目>-bc sh -c 'llvm-nm -u ~/bc/*.bc'
   ```

   **验证标准**：输出应该只包含标准 libc/系统库函数（如 `malloc`, `printf`, `pthread_*` 等）

注意：bc 文件会在 GitHub Actions 构建时自动提取并发布到 Release 中，不需要手动复制或使用 Git LFS 提交。

---

# 第二部分：AFL++ Fuzzing 设置（统一版）

## 基础镜像与工具链

- 基础镜像：`aflplusplus/aflplusplus:latest`
- 使用 `afl-clang-lto` 进行编译（防止 hash 碰撞）
- 启用 CMPLOG 以获得更好的覆盖
- 推荐 CFLAGS：`-O2`（优化速度）

### Fuzzing 效率优化
1. **不使用 Address Sanitizer**：影响运行速度
2. **使用 afl-clang-lto**：防止碰撞，提高覆盖精度
3. **启用 CMPLOG**：更好地处理比较操作
4. **静态链接**：减少运行时开销

## fuzz.dockerfile 统一模板

新的 fuzz.dockerfile 将 fuzz/cmplog/cov/uftrace 的所有构建逻辑合并到一个文件中。参考 jq 项目的结构。

### 核心原则
- **一开始先安装基本包**：htop, vim, tmux，然后再安装编译依赖（包括 uftrace）
- **所有工作在 /work 目录下进行**
- **项目名称、版本、源码来源保存到 /work/proj 文件中**
- **只下载一份源码**，然后解压多份到 `/work/build-{fuzz,cmplog,cov,uftrace}`
- **在这些目录中分别编译**
- **如果需要install**，安装到目录 `/work/install-{fuzz,cmplog,cov,uftrace}`
- **使用 `/work/bin-{fuzz,cmplog,cov,uftrace}` 软链接到 build/install 生成的 binary**
- **Fuzz 相关资源放到 `/work/{dict,in,fuzz.sh,whatsup.sh}` 中**
- **进入 docker 容器的时候，默认到 /work 的 bash 中**
- **Dockerfile 需要明确区分各个阶段**：config, make, install, 创建软链接等步骤在一个阶段内完全做好，再到另一个阶段

### 模板结构（以 autotools 项目为例）

```dockerfile
FROM aflplusplus/aflplusplus:latest

# Install basic packages first
RUN apt-get update && \
    apt-get install -y htop vim tmux parallel jdupes rdfind && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget <其他依赖> uftrace && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /work

# Save project metadata
RUN echo "project: <项目名>" > /work/proj && \
    echo "version: <版本号>" >> /work/proj && \
    echo "source: <源码URL>" >> /work/proj

# Download source once and extract to multiple build directories
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 <源码URL> && \
    tar -xzf <压缩包> && \
    rm <压缩包> && \
    cp -a <源码目录> build-fuzz && \
    cp -a <源码目录> build-cmplog && \
    cp -a <源码目录> build-cov && \
    cp -a <源码目录> build-uftrace && \
    rm -rf <源码目录>

# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure <配置选项> && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/<binary路径> bin-fuzz && \
    /work/bin-fuzz --version

# Build cmplog binary with afl-clang-lto + CMPLOG
WORKDIR /work/build-cmplog
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    ./configure <配置选项> && \
    AFL_LLVM_CMPLOG=1 make -j$(nproc)

WORKDIR /work
RUN ln -s build-cmplog/<binary路径> bin-cmplog && \
    /work/bin-cmplog --version

# Copy fuzzing resources
COPY <项目>/fuzz/dict /work/dict
COPY <项目>/fuzz/in /work/in
COPY <项目>/fuzz/fuzz.sh /work/fuzz.sh
COPY <项目>/fuzz/whatsup.sh /work/whatsup.sh

# Build cov binary with llvm-cov instrumentation
WORKDIR /work/build-cov
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate -fcoverage-mapping -static -Wl,--allow-multiple-definition" \
    ./configure <配置选项> && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-cov/<binary路径> bin-cov && \
    /work/bin-cov --version && \
    rm -f *.profraw

# Build uftrace binary with profiling instrumentation
WORKDIR /work/build-uftrace
RUN CC=clang \
    CXX=clang++ \
    CFLAGS="-g -O0 -pg -fno-omit-frame-pointer" \
    LDFLAGS="-pg -Wl,--allow-multiple-definition" \
    ./configure --prefix=/work/install-uftrace <其他配置选项> && \
    make -j$(nproc) && \
    make install

WORKDIR /work
RUN ln -s install-uftrace/bin/<binary> bin-uftrace && \
    /work/bin-uftrace --version && \
    rm -f gmon.out

# Default to bash in /work
WORKDIR /work
CMD ["/bin/bash"]
```

### CMake 项目调整

对于 CMake 项目，使用相同的目录结构，但用 cmake 命令替代 configure：

```dockerfile
# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN mkdir build && cd build && \
    CC=afl-clang-lto CXX=afl-clang-lto++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-O2" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DBUILD_SHARED_LIBS=OFF \
        <其他CMake选项> && \
    make -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/build/<binary路径> bin-fuzz
```

### Make 项目调整

对于 Make 项目（如 QuickJS），直接在构建目录使用 make：

```dockerfile
# Build fuzz binary with afl-clang-lto
WORKDIR /work/build-fuzz
RUN make CC=afl-clang-lto \
    CFLAGS="-O2 <其他标志>" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    <目标> \
    -j$(nproc)

WORKDIR /work
RUN ln -s build-fuzz/<binary> bin-fuzz
```

## Fuzzing 资源文件

### 字典文件 (dict)
优先使用现有资源：
- OSS-Fuzz: https://github.com/google/oss-fuzz/tree/master/projects
- AFL++: https://github.com/AFLplusplus/AFLplusplus/tree/stable/dictionaries
- 项目自身的 fuzzing 资源

如无现有资源，根据项目语法创建。

### 输入语料库 (in/)
- 包含有效的小型输入文件
- 覆盖不同的输入类型和边界情况
- 文件尽量小（< 1KB）

### Fuzzing 脚本 (fuzz.sh)

参考 `jq/fuzz/fuzz.sh` 模板，新项目的 fuzz.sh 应包含：
- 命令行参数解析 (`-j N` 控制并行数)
- 完整的使用说明
- 二进制文件存在性检查
- 无内存限制 (`-m none`)
- CMPLOG 支持（如果 `.cmplog` 文件存在）
- 并行模式下的进程管理和信号处理
- 主 fuzzer (Master) 和从 fuzzer (Slaves) 的区分

**重要**：使用新的统一路径结构：
- CMPLOG_BIN 使用 `bin-cmplog` 而不是 `<binary>.cmplog`
- TARGET_BIN 使用 `bin-fuzz` 而不是 `<binary>`

```bash
#!/usr/bin/env bash
# Fuzzing script for <项目> using AFL++
# Optimized: Parallel execution support (-j), unlimited memory, cleanup handling.

set -e

# --- Default Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"
IN_DIR="${SCRIPT_DIR}/in"
DICT="${SCRIPT_DIR}/dict"
CMPLOG_BIN="${SCRIPT_DIR}/bin-cmplog"
TARGET_BIN="${SCRIPT_DIR}/bin-fuzz"
PARALLEL=1

# --- Usage Function ---
usage() {
    echo "Usage: $0 [-j N]"
    echo "  -j N   Number of parallel fuzzers (Default: 1)"
    echo "         If N=1: Runs in foreground with TUI."
    echo "         If N>1: Runs in background (headless) with 1 Master and N-1 Slaves."
    exit 1
}

# --- Parse Arguments ---
while getopts ":j:" opt; do
  case ${opt} in
    j)
      PARALLEL=${OPTARG}
      ;;
    \?)
      echo "Invalid option: -${OPTARG}" >&2
      usage
      ;;
    :)
      echo "Option -${OPTARG} requires an argument." >&2
      usage
      ;;
  esac
done

# Validate Parallel Number
if ! [[ "$PARALLEL" =~ ^[0-9]+$ ]] || [ "$PARALLEL" -le 0 ]; then
    echo "Error: Parallel count must be an integer > 0."
    exit 1
fi

# Ensure output directory exists
mkdir -p "${OUT_DIR}"

echo "=== <项目> AFL++ Fuzzing ==="
echo "Target:           ${TARGET_BIN}"
echo "Input corpus:     ${IN_DIR}"
echo "Output directory: ${OUT_DIR}"
echo "Dictionary:       ${DICT}"
echo "Parallel jobs:    ${PARALLEL}"
echo "Memory Limit:     Unlimited (-m none)"
echo ""

# Check for binaries
if [ ! -x "$TARGET_BIN" ]; then
    echo "Error: Target binary not found at $TARGET_BIN"
    exit 1
fi

# Base AFL arguments
# -m none: No memory limit
AFL_ARGS="-i ${IN_DIR} -o ${OUT_DIR} -x ${DICT} -m none"

# --- Fuzzing Logic ---

if [ "${PARALLEL}" -eq 1 ]; then
    # === Serial Mode (Interactive TUI) ===
    echo "Starting single fuzzer (Interactive Mode)..."

    # Check if cmplog binary exists
    CMPLOG_ARGS=""
    if [ -x "${CMPLOG_BIN}" ]; then
        echo "Enabled CMPLOG."
        CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    fi

    afl-fuzz \
        ${AFL_ARGS} \
        ${CMPLOG_ARGS} \
        -- "${TARGET_BIN}" <参数> @@

else
    # === Parallel Mode (Headless) ===
    echo "Starting parallel fuzzers..."
    echo "Mode: 1 Master + $((PARALLEL - 1)) Slaves"
    echo "Logs are suppressed. Use 'afl-whatsup ${OUT_DIR}' to monitor progress."

    # Trap Ctrl+C (SIGINT) to kill all background processes
    pids=()
    trap 'echo "Stopping all fuzzers..."; kill ${pids[@]} 2>/dev/null; wait; exit' SIGINT SIGTERM

    # 1. Start Master (Main)
    # Master handles CMPLOG (if available) and deterministic checks
    CMPLOG_ARGS=""
    if [ -x "${CMPLOG_BIN}" ]; then
        CMPLOG_ARGS="-c ${CMPLOG_BIN}"
    fi

    echo "[+] Starting Master fuzzer..."
    afl-fuzz \
        ${AFL_ARGS} \
        ${CMPLOG_ARGS} \
        -M main \
        -- "${TARGET_BIN}" <参数> @@ >/dev/null 2>&1 &

    pids+=($!)

    # Give master a moment to initialize structure
    sleep 2

    # 2. Start Slaves (Secondary)
    # Slaves focus on throughput/havoc, usually don't need CMPLOG to save CPU
    for i in $(seq 1 $((PARALLEL - 1))); do
        echo "[+] Starting Slave fuzzer #$i..."
        afl-fuzz \
            ${AFL_ARGS} \
            -S "slave${i}" \
            -- "${TARGET_BIN}" <参数> @@ >/dev/null 2>&1 &

        pids+=($!)
    done

    echo ""
    echo "All ${PARALLEL} fuzzers are running in background."
    echo "PID list: ${pids[@]}"
    echo "Press Ctrl+C to stop all instances."

    # Wait indefinitely for children
    wait
fi
```

### 监控脚本 (whatsup.sh)

参考 `jq/fuzz/whatsup.sh` 模板，用于监控 fuzzing 进度：

```bash
#!/usr/bin/env bash
# Monitor AFL++ fuzzing progress
# Usage: ./whatsup.sh [-w]
#   -w: Watch mode (refresh every 2 seconds)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/findings"

# 检查 afl-whatsup 是否存在
if ! command -v afl-whatsup &> /dev/null; then
    echo "Error: 'afl-whatsup' command not found. Please ensure AFL++ is installed and in your PATH."
    exit 1
fi

# 检查输出目录是否存在
if [ ! -d "${OUT_DIR}" ]; then
    echo "Error: Output directory '${OUT_DIR}' does not exist yet."
    echo "Please start the fuzzing script first."
    exit 1
fi

# 处理参数
WATCH_MODE=0

while getopts ":w" opt; do
  case ${opt} in
    w)
      WATCH_MODE=1
      ;;
    \?)
      echo "Invalid option: -${OPTARG}" >&2
      exit 1
      ;;
  esac
done

if [ "${WATCH_MODE}" -eq 1 ]; then
    # 检查 watch 命令是否存在
    if command -v watch &> /dev/null; then
        echo "Starting watch mode (Press Ctrl+C to exit)..."
        # 使用 watch 命令每 2 秒刷新一次，-c 支持颜色输出
        watch -n 2 -c "afl-whatsup -s ${OUT_DIR}"
    else
        echo "Error: 'watch' command not found. Running once instead."
        afl-whatsup -s "${OUT_DIR}"
    fi
else
    # 单次运行
    echo "=== AFL++ Status Report ==="
    echo "Dir: ${OUT_DIR}"
    echo ""
    # -s 参数表示 summary (摘要)，如果想看详细每个核心的状态，去掉 -s
    afl-whatsup -s "${OUT_DIR}"
fi
```

### readme.md
```markdown
# <项目> Fuzzing Resources

## External Resources

- dict: 来源于 <URL> (如 OSS-Fuzz)
- in/: 自行创建 / 来源于 <URL>

## Usage

```bash
cd dataset
docker build -f <项目>/fuzz.dockerfile -t <项目>-fuzz .
docker run -it --rm <项目>-fuzz
```

在容器内，可以使用：
- `/work/bin-fuzz` - AFL++ fuzzing 二进制
- `/work/bin-cmplog` - AFL++ CMPLOG 二进制
- `/work/bin-cov` - LLVM coverage 二进制
- `/work/bin-uftrace` - uftrace profiling 二进制
- `/work/fuzz.sh` - 启动 fuzzing
- `/work/whatsup.sh` - 监控 fuzzing 进度

## Fuzzing 验证步骤

1. 构建 Docker 镜像（在 dataset 目录下执行）：
   ```bash
   cd dataset
   docker build -f <项目>/fuzz.dockerfile -t <项目>-fuzz .
   ```

2. 验证 binary 正常工作：
   ```bash
   docker run --rm <项目>-fuzz /work/bin-fuzz --version
   docker run --rm <项目>-fuzz /work/bin-cmplog --version
   ```

3. 验证容器结构：
   ```bash
   docker run --rm <项目>-fuzz /bin/bash -c "ls -la /work/ && cat /work/proj"
   ```

4. 启动 fuzzing（测试）：
   ```bash
   docker run -it --rm <项目>-fuzz timeout 60 ./fuzz.sh
   ```

注意：fuzzing 二进制文件会在 GitHub Actions 构建时自动提取并发布到 Release 中，不需要手动复制或使用 Git LFS 提交。

---

# 第三部分：常见问题处理

## 静态链接与共享库冲突
如果某些程序需要构建共享库（如 stdbuf），在 configure 时禁用：
```dockerfile
./configure --enable-no-install-program=stdbuf
```

## extract-bc 需要 file 命令
确保安装 `file` 包：
```dockerfile
RUN apt-get install -y file
```

## 多重定义错误
静态链接 glibc 时会遇到多重定义错误，需要添加：
```dockerfile
LDFLAGS="-static -Wl,--allow-multiple-definition"
```

## 预期的常见未定义符号
以下符号在静态链接后仍可能显示为未定义，这是正常的：
- 标准 C 库：`malloc`, `free`, `printf`, `fprintf`, `fopen`, `fclose`, `strlen`, `strcmp` 等
- 数学库：`sin`, `cos`, `sqrt`, `log`, `exp` 等
- 线程库：`pthread_create`, `pthread_mutex_*` 等
- 系统调用包装：`open`, `close`, `read`, `write`, `mmap`, `stat` 等
