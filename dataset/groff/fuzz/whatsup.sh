#!/usr/bin/env bash
afl-whatsup -s "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/findings"
