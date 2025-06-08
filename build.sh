#!/bin/bash

case $1 in
  "server")
    (
      cd ./server || exit 1
      cargo build --release
    )
    ;;
    
  "client")
    echo "Building client crates"
    (
      cd ./cli || exit 1
      cargo build --release
    )
    (
      cd ./client-service || exit 1
      cargo build --release
    )
    ;;
    
  *)
    echo "Missing build argument (server/client)"
    exit 1
    ;;
esac
