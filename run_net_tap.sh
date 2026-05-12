#!/usr/bin/env bash
cargo build

if [[ "$OSTYPE" == "darwin"* ]]; then
  etho="lo0"
else
  etho="lo"
fi

sudo ./target/debug/net-tap \
  --port 9002 \
  --proto sse \
  --iface "$etho"
