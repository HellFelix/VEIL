#!/bin/bash

OS=$(uname)

if [[ $OS == "Darwin" ]]; then
  VEIL_CLI="/usr/local/bin/veil-cli"
elif [[ $OS == "Linux" ]]; then
  VEIL_CLI="/bin/veil-cli"
fi

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
