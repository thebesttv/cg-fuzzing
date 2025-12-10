# wget Retry Parameters Script

## 概述

`add_wget_retry.py` 是一个自动化脚本，用于检查和添加 wget 命令的重试参数，防止网络问题导致构建失败。

## 功能

- 自动扫描所有 `*.dockerfile` 文件
- 检测 wget 命令是否有 retry 参数
- 自动添加标准 retry 参数：`--tries=3 --retry-connrefused --waitretry=5`
- 如果已有不同的 retry 参数，替换为标准参数并打印警告
- 智能过滤包管理器安装命令（如 `apt-get install wget`）
- 直接原地修改文件（inplace）
- 仅打印警告和总结信息，保持输出简洁

## 使用方法

### 基本用法

```bash
# 在当前目录及子目录下处理所有 .dockerfile 文件
python3 add_wget_retry.py

# 指定目录
python3 add_wget_retry.py --root-dir /path/to/project

# 预览模式（不实际修改文件）
python3 add_wget_retry.py --dry-run
```

### 示例输出

```bash
$ python3 add_wget_retry.py
============================================================
Processed 452 Dockerfile(s)
Modified 444 file(s)
============================================================
```

如果发现不同的 retry 参数，会显示警告：

```bash
WARNING: test.dockerfile:2
  Found different retry parameters: -t 5
  Replacing with standard: --tries=3 --retry-connrefused --waitretry=5
```

## 标准 retry 参数说明

- `--tries=3`: 重试 3 次
- `--retry-connrefused`: 即使连接被拒绝也重试
- `--waitretry=5`: 每次重试等待 5 秒

这些参数可以有效应对临时网络问题，提高 Docker 构建的成功率。

## 注意事项

- 脚本会智能识别并跳过包管理器的 wget 安装命令（如 `apt-get install wget`）
- 只处理实际的文件下载命令
- 修改是原地进行的，不会创建备份文件
- 已有正确参数的文件不会被修改
