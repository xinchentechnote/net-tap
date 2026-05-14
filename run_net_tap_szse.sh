#!/usr/bin/env bash
cargo build

if [[ "$OSTYPE" == "darwin"* ]]; then
  etho="lo0"
else
  etho="lo"
fi

sudo ./target/debug/net-tap \
  --bpf "tcp port 9003" \
  --proto szse \
  --iface "$etho"
