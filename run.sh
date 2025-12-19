#!/bin/bash
export LD_LIBRARY_PATH=/usr/local/lib/:$LD_LIBRARY_PATH
set -e
PACKAGE_NAME="torch"
PACKAGE_PATH=$(pip show "$PACKAGE_NAME" 2>/dev/null | grep -i "^Location:" | awk '{print $2}')
export LD_LIBRARY_PATH="${PACKAGE_PATH}/${PACKAGE_NAME}/lib":$LD_LIBRARY_PATH

# 在运行可执行文件之前 需要先将上述命令在对应窗口执行