#!/bin/bash
# Ralph Loop — 1-hour autonomous Ox Security experiment runner
# Usage: ./ralph-loop.sh [hours]
#
# Each iteration: Claude reads RALPH.md, picks highest-value experiment, ships it.

set -uo pipefail

# Allow nested Claude sessions
unset CLAUDECODE 2>/dev/null || true
unset CLAUDE_CODE_ENTRYPOINT 2>/dev/null || true

HOURS=${1:-1}
END_TIME=$(($(date +%s) + HOURS * 3600))
ITERATION=0
MAX_CONSECUTIVE_FAILURES=5
CONSECUTIVE_FAILURES=0
LOG_DIR="/home/ubuntu/study-ox-security/ralph-logs"
PROJECT_DIR="/home/ubuntu/study-ox-security"
STATE_FILE="$LOG_DIR/ralph-state.json"
CLAUDE_TIMEOUT=600  # 10 minutes per iteration
COOLDOWN_BASE=15    # 15s cooldown between iterations (shorter for 1hr)
RATE_LIMIT_WAIT=300 # 5 min wait on rate limit

mkdir -p "$LOG_DIR"

echo "=============================================="
echo " Ralph Loop — Ox Security Experiment Runner"
echo " Duration: ${HOURS} hours"
echo " End time: $(date -d @$END_TIME)"
echo " Timeout per iteration: ${CLAUDE_TIMEOUT}s"
echo " Log dir: $LOG_DIR"
echo "=============================================="

save_state() {
    cat > "$STATE_FILE" <<STATEEOF
{
  "iteration": $ITERATION,
  "started": "$(date -d @$((END_TIME - HOURS * 3600)) -Iseconds)",
  "end_time": $END_TIME,
  "consecutive_failures": $CONSECUTIVE_FAILURES,
  "last_update": "$(date -Iseconds)"
}
STATEEOF
}

while [ $(date +%s) -lt $END_TIME ]; do
    ITERATION=$((ITERATION + 1))
    REMAINING_MIN=$(( (END_TIME - $(date +%s)) / 60 ))
    ITER_LOG="$LOG_DIR/iteration-$(printf '%03d' $ITERATION)-$(date +%Y%m%d-%H%M%S).log"

    echo ""
    echo "========================================"
    echo " Iteration $ITERATION — $(date)"
    echo " Time remaining: $REMAINING_MIN minutes"
    echo " Consecutive failures: $CONSECUTIVE_FAILURES"
    echo "========================================"

    save_state

    PROMPT="You are Ralph, an autonomous experiment runner for the study-ox-security project.
Read /home/ubuntu/study-ox-security/RALPH.md for your full strategy and experiment backlog.

This is iteration $ITERATION. $REMAINING_MIN minutes remaining in this session.

## Your task this iteration:

1. Read RALPH.md for the experiment backlog and strategy
2. Read CHANGELOG.md to see what's already been done — NEVER repeat work
3. Pick the SINGLE highest-priority uncompleted experiment
4. Implement it completely — working code, tested, documented
5. Update RALPH.md to mark the experiment as done ([x])
6. Append what you did to CHANGELOG.md with ISO timestamp
7. Run: git add . && git commit -m 'experiment: {what you built}' && git push
8. Print a one-line summary of what you accomplished

IMPORTANT RULES:
- Read CHANGELOG.md FIRST to avoid repeating work
- One experiment per iteration — ship it completely
- All scripts go in scripts/ and must be runnable with node scripts/<name>.js
- Results/data go in experiments/ directory
- No external npm dependencies — Node.js built-ins only (fetch, fs, path, etc.)
- If the Ox Security API returns auth errors, build the script with mock data and note it
- Keep code clean and well-commented
- git push is REQUIRED — the repo auto-deploys
- If something fails, log it in CHANGELOG.md and move to the next experiment"

    cd "$PROJECT_DIR"
    timeout "$CLAUDE_TIMEOUT" env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT \
        claude --dangerously-skip-permissions -p "$PROMPT" \
        --max-turns 25 \
        2>&1 | tee "$ITER_LOG"
    EXIT_CODE=$?

    if [ $EXIT_CODE -eq 0 ]; then
        echo "Iteration $ITERATION completed successfully."
        CONSECUTIVE_FAILURES=0
        COOLDOWN=$COOLDOWN_BASE
    elif [ $EXIT_CODE -eq 124 ]; then
        echo "Iteration $ITERATION timed out after ${CLAUDE_TIMEOUT}s."
        echo "$(date -Iseconds) — Iteration $ITERATION: TIMEOUT (${CLAUDE_TIMEOUT}s)" >> "$PROJECT_DIR/CHANGELOG.md"
        CONSECUTIVE_FAILURES=$((CONSECUTIVE_FAILURES + 1))
        COOLDOWN=$COOLDOWN_BASE
    else
        echo "Iteration $ITERATION failed with exit code $EXIT_CODE."

        if grep -qi "rate.limit\|429\|too many\|overloaded" "$ITER_LOG" 2>/dev/null; then
            echo "Rate limit detected. Waiting ${RATE_LIMIT_WAIT}s..."
            COOLDOWN=$RATE_LIMIT_WAIT
        else
            COOLDOWN=$((COOLDOWN_BASE * (CONSECUTIVE_FAILURES + 1)))
            [ $COOLDOWN -gt 300 ] && COOLDOWN=300
        fi

        echo "$(date -Iseconds) — Iteration $ITERATION: FAILED (exit=$EXIT_CODE)" >> "$PROJECT_DIR/CHANGELOG.md"
        CONSECUTIVE_FAILURES=$((CONSECUTIVE_FAILURES + 1))
    fi

    # Check consecutive failure limit
    if [ $CONSECUTIVE_FAILURES -ge $MAX_CONSECUTIVE_FAILURES ]; then
        echo "Hit $MAX_CONSECUTIVE_FAILURES consecutive failures. Resetting counter and waiting 5 minutes."
        CONSECUTIVE_FAILURES=0
        COOLDOWN=300
    fi

    # Check if we still have time
    if [ $(date +%s) -ge $END_TIME ]; then
        break
    fi

    echo "Sleeping ${COOLDOWN}s before next iteration..."
    sleep $COOLDOWN
done

save_state

echo ""
echo "=============================================="
echo " Ralph Loop complete!"
echo " Total iterations: $ITERATION"
echo " End time: $(date)"
echo " Check $LOG_DIR for logs"
echo "=============================================="
