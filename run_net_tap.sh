#!/usr/bin/env bash
cargo fix --allow-dirty
cargo build

if [[ "$OSTYPE" == "darwin"* ]]; then
  etho="lo0"
else
  etho="lo"
fi

sudo ./target/debug/net-tap --config ./config/config_$etho.toml
