# 1. 递归查找当前目录及子目录下所有的 .c 文件
SRCS := $(shell find . -type f -name "*.c")

# 将 .c 替换为以 .cov 结尾的可执行目标（便于批量删除）
BINARIES := $(patsubst %.c,%.cov,$(SRCS))

# Docker 配置：使用 AFL++ 镜像（包含 llvm 和 afl 工具链）
DOCKER_IMAGE := aflplusplus/aflplusplus:latest
MOUNT_DIR    := /data
CURRENT_DIR  := $(CURDIR)

# 编译器与覆盖相关标志（llvm-cov 需要这两项）
CC := clang
COVERAGE_CFLAGS := -fprofile-instr-generate -fcoverage-mapping -g -O0
LLVM_PROFDATA ?= llvm-profdata
LLVM_COV ?= llvm-cov

# 定义伪目标
.PHONY: build docker-build clean distclean

docker-build:
	docker run --rm -t \
		-u $(shell id -u):$(shell id -g) \
		-v "$(CURRENT_DIR):$(MOUNT_DIR)" \
		$(DOCKER_IMAGE) \
		bash -c "make -C $(MOUNT_DIR) build"

# 默认目标：仅在本地构建所有覆盖仪器化的二进制
build: $(BINARIES)

# 将 each .c 编译为同名 .cov 二进制，启用 llvm-cov 覆盖插桩
%.cov: %.c
	@echo "CC $(CC) $(COVERAGE_CFLAGS) -o $@ $<"
	$(CC) $(COVERAGE_CFLAGS) $< -o $@

# 把 <name>.profraw 合并为 <name>.profdata 并导出为 <name>.json
# 用法示例: make -C coverage path/to/foo.json
%.json: %.profraw %.cov
	@echo "$(LLVM_PROFDATA) merge -sparse $< -o $*.profdata"
	$(LLVM_PROFDATA) merge -sparse $< -o $*.profdata
	@echo "$(LLVM_COV) export $(patsubst %.json,%.cov,$@) -instr-profile=$*.profdata -format=json > $@"
	$(LLVM_COV) export $(patsubst %.json,%.cov,$@) -instr-profile=$*.profdata -format=json > $@
	@rm -f $*.profdata

clean:
	find . -type f \( -name "*.profraw" -o -name "*.profdata" -o -name "*.json" -o -name "core.*" \) -delete -print

distclean: clean
	find . -type f -name "*.cov" -delete -print
