#!/usr/bin/env bash
set -e

if ! command -v docker >/dev/null; then
  echo "Docker is not installed. Please install Docker." >&2
  exit 1
fi
COMPOSE=""
if command -v docker-compose >/dev/null; then
  COMPOSE="docker-compose"
elif docker compose version >/dev/null 2>&1; then
  COMPOSE="docker compose"
else
  echo "Docker Compose is not installed. Please install it." >&2
  exit 1
fi

LOCKON_DEBUG_PORT=${LOCKON_DEBUG_PORT:-5678} $COMPOSE up --build
