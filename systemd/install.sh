#!/bin/bash

OS="$(uname)"

mkdir -p /etc/veil
cp ./veil.conf /etc/veil

if [[ "$OS" == "Darwin" ]]; then
    echo "Running on macOS"
elif [[ "$OS" == "Linux" ]]; then
    echo "Found Linux system"
    cp ./veil.service /etc/systemd/system/
else
    echo "Unsupported OS: $OS"
fi
