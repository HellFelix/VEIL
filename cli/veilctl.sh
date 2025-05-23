#!/bin/bash

# Optional: point to your actual tool or backend handler
VEIL_CLI="/bin/veil-cli"

journalctl -fu veil.service --no-pager --since=now &
LOG_PID=$!

# Handle Ctrl+C to clean up background log stream
trap "kill $LOG_PID 2>/dev/null; exit" INT TERM

while true; do
    # Show the prompt
    read -rp "[veil]# " cmd

    # Exit commands
    if [[ "$cmd" == "exit" || "$cmd" == "quit" ]]; then
        break
    fi

    # Skip empty input
    if [[ -z "$cmd" ]]; then
        continue
    else
        eval $VEIL_CLI "$cmd"
    fi
done

kill -9 $(pidof journalctl)
