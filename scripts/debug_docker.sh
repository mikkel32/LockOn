#!/usr/bin/env bash
set -e

if ! command -v docker >/dev/null; then
  echo "Docker is not installed. Please install Docker." >&2
  exit 1
fi
if ! command -v docker-compose >/dev/null; then
  echo "docker-compose is not installed. Please install it." >&2
  exit 1
fi

LOCKON_DEBUG_PORT=${LOCKON_DEBUG_PORT:-5678} docker-compose up --build
