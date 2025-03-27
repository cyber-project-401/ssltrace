#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <container_name_or_id>"
  exit 1
fi

container="$1"
pid=$(docker inspect --format '{{.State.Pid}}' "$container" 2>/dev/null)

if [ -z "$pid" ]; then
  echo "❌ Could not find PID for container '$container'"
  exit 1
fi

# Look for libssl.so.3 in the container's memory maps
sudo grep 'libssl.so' /proc/$pid/maps | awk '{print $6}' | sort -u

