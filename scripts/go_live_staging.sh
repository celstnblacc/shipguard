#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.staging.yml"
ENV_FILE="$ROOT_DIR/.env.staging"
ENV_EXAMPLE="$ROOT_DIR/.env.staging.example"
SERVICE="shipguard-runner"
MAX_HEALTH_WAIT="${MAX_HEALTH_WAIT:-60}"

usage() {
  cat <<USAGE
Usage: scripts/go_live_staging.sh <up|down|status|logs>

Commands:
  up      Build and start local staging, then wait for health check
  down    Stop and remove local staging stack
  status  Show compose service status
  logs    Tail service logs
USAGE
}

require_compose() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is not installed." >&2
    exit 1
  fi
  if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: docker compose is not available." >&2
    exit 1
  fi
}

ensure_env() {
  if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
      cp "$ENV_EXAMPLE" "$ENV_FILE"
      echo "Created $ENV_FILE from template. Review values before real staging use."
    else
      echo "ERROR: missing $ENV_FILE and $ENV_EXAMPLE." >&2
      exit 1
    fi
  fi
}

wait_for_health() {
  local cid health
  cid="$(docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps -q "$SERVICE")"
  if [ -z "$cid" ]; then
    echo "ERROR: service $SERVICE container id not found." >&2
    exit 1
  fi

  for _ in $(seq 1 "$MAX_HEALTH_WAIT"); do
    health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid")"
    if [ "$health" = "healthy" ]; then
      echo "Service health: healthy"
      return 0
    fi
    sleep 1
  done

  echo "ERROR: service did not become healthy within ${MAX_HEALTH_WAIT}s." >&2
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps
  exit 1
}

cmd="${1:-}"
case "$cmd" in
  up)
    require_compose
    ensure_env
    docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build
    wait_for_health
    docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps
    ;;
  down)
    require_compose
    ensure_env
    docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down
    ;;
  status)
    require_compose
    ensure_env
    docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps
    ;;
  logs)
    require_compose
    ensure_env
    docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" logs -f --tail=200 "$SERVICE"
    ;;
  *)
    usage
    exit 1
    ;;
esac
