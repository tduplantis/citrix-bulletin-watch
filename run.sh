#!/usr/bin/env bash
# Hourly runner: scrape inside the container, then commit and push bulletins.json
# when watch.py leaves a commit reason. Logs to $BASE/logs, one file per UTC day, 14 kept.
set -uo pipefail

BASE="${CBW_BASE:-$HOME/citrix-bulletin-watch}"
REPO="$BASE/repo"
STATE="$BASE/state"
LOGS="$BASE/logs"
mkdir -p "$STATE" "$LOGS"

LOG="$LOGS/cbw-$(date -u +%F).log"
if [ -t 1 ]; then exec > >(tee -a "$LOG") 2>&1; else exec >>"$LOG" 2>&1; fi

exec 9>"$STATE/run.lock"
flock -n 9 || { echo "$(date -u +%FT%TZ) previous run still active, skipping"; exit 0; }

find "$LOGS" -name 'cbw-*.log' -mtime +13 -delete
echo "=== $(date -u +%FT%TZ) run start"

# Image tag follows the code, so editing watch.py or the Dockerfile triggers a rebuild.
TAG=$(cat "$REPO/Dockerfile" "$REPO/watch.py" | sha256sum | cut -c1-12)
IMAGE="citrix-bulletin-watch:$TAG"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "building $IMAGE"
    docker build -q -t "$IMAGE" "$REPO" || { echo "docker build failed"; exit 1; }
fi

docker run --rm --init --ipc=host \
    -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$REPO:/repo" -v "$STATE:/state" \
    "$IMAGE"
echo "watch.py exit $?"

cd "$REPO" || exit 1
if [ -s "$STATE/commit-reason" ]; then
    reason=$(head -1 "$STATE/commit-reason")
    git add bulletins.json
    if git diff --cached --quiet; then
        echo "nothing staged for '$reason'"
    else
        git commit -q -m "bulletins: $reason" && echo "committed: $reason"
    fi
    rm -f "$STATE/commit-reason"
fi

# Push anything not yet on origin, including commits from an earlier failed push.
git fetch -q origin main
if [ -n "$(git rev-list origin/main..main)" ]; then
    git pull -q --rebase origin main && git push -q origin main && echo "pushed" || echo "push failed, will retry next run"
fi
echo "=== $(date -u +%FT%TZ) run end"
