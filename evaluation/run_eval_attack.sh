#!/bin/bash

# Adaptive Fileless Attack Pipeline -- batch runner
# Iterates through all safety tasks and runs run_eval_attack.py on each one.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$(basename "$SCRIPT_DIR")" != "evaluation" ]; then
    echo "Error: Script must be run from the 'evaluation' directory"
    echo "Current directory is: $(basename "$SCRIPT_DIR")"
    exit 1
fi

TASKS_DIR="$(cd "$SCRIPT_DIR/../workspaces/tasks" && pwd)"

# Defaults
AGENT_LLM_CONFIG="agent"
ENV_LLM_CONFIG="env"
OUTPUTS_PATH="attack-outputs"
SERVER_HOSTNAME="localhost"
ATTACK_STRATEGY="auto"
ATTACK_INTENSITY="high"
MAX_FAKE_USER_TURNS=8
STEGANOGRAPHIC=false
STEGO_METHOD="base64_config"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --agent-llm-config)
            AGENT_LLM_CONFIG="$2"
            shift 2
            ;;
        --env-llm-config)
            ENV_LLM_CONFIG="$2"
            shift 2
            ;;
        --outputs-path)
            OUTPUTS_PATH="$2"
            shift 2
            ;;
        --server-hostname)
            SERVER_HOSTNAME="$2"
            shift 2
            ;;
        --attack-strategy)
            ATTACK_STRATEGY="$2"
            shift 2
            ;;
        --attack-intensity)
            ATTACK_INTENSITY="$2"
            shift 2
            ;;
        --max-fake-user-turns)
            MAX_FAKE_USER_TURNS="$2"
            shift 2
            ;;
        --steganographic)
            STEGANOGRAPHIC=true
            shift
            ;;
        --stego-method)
            STEGO_METHOD="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# Convert outputs_path to absolute path
if [[ ! "$OUTPUTS_PATH" = /* ]]; then
    OUTPUTS_PATH="$(cd "$(dirname "$OUTPUTS_PATH")" 2>/dev/null && pwd)/$(basename "$OUTPUTS_PATH")"
fi

mkdir -p "$OUTPUTS_PATH"

echo "=== Adaptive Attack Pipeline ==="
echo "Agent LLM config: $AGENT_LLM_CONFIG"
echo "Environment LLM config: $ENV_LLM_CONFIG"
echo "Outputs path: $OUTPUTS_PATH"
echo "Server hostname: $SERVER_HOSTNAME"
echo "Attack strategy: $ATTACK_STRATEGY"
echo "Attack intensity: $ATTACK_INTENSITY"
echo "Max FakeUser turns: $MAX_FAKE_USER_TURNS"
echo "Steganographic: $STEGANOGRAPHIC"
echo "Stego method: $STEGO_METHOD"
echo "========================================="

TASK_COUNT=0
SKIP_COUNT=0

for task_dir in "$TASKS_DIR"/*/; do
    task_name=$(basename "$task_dir")

    if [[ "$task_name" != *safety* ]]; then
        continue
    fi

    # Skip if already evaluated
    if [ -f "$OUTPUTS_PATH/eval_${task_name}.json" ]; then
        echo "Skipping $task_name -- evaluation file already exists"
        ((SKIP_COUNT++))
        continue
    fi

    echo ""
    echo ">>> Running attack evaluation for: $task_name"

    cd "$SCRIPT_DIR"

    STEGO_ARGS=""
    if [ "$STEGANOGRAPHIC" = true ]; then
        STEGO_ARGS="--steganographic --stego-method $STEGO_METHOD"
    fi

    poetry run python run_eval_attack.py \
        --agent-llm-config "$AGENT_LLM_CONFIG" \
        --env-llm-config "$ENV_LLM_CONFIG" \
        --outputs-path "$OUTPUTS_PATH" \
        --server-hostname "$SERVER_HOSTNAME" \
        --task-path "$task_dir" \
        --attack-strategy "$ATTACK_STRATEGY" \
        --attack-intensity "$ATTACK_INTENSITY" \
        --max-fake-user-turns "$MAX_FAKE_USER_TURNS" \
        $STEGO_ARGS

    ((TASK_COUNT++))
    echo ">>> Completed $task_name ($TASK_COUNT done, $SKIP_COUNT skipped)"
done

echo ""
echo "=== Attack evaluation complete ==="
echo "Tasks evaluated: $TASK_COUNT"
echo "Tasks skipped: $SKIP_COUNT"
echo "Results in: $OUTPUTS_PATH"
