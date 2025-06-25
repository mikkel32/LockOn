#!/usr/bin/env bash
set -e

python scripts/manage_vm.py start --port "${LOCKON_DEBUG_PORT:-5678}" "$@"
