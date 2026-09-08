#!/bin/sh
set -eu

interface_name=$(ip -o -4 route show to default | awk '{print $5; exit}')
if [ -z "$interface_name" ]; then
  echo "Unable to determine the primary IPv4 interface" >&2
  exit 1
fi

interface_cidr=$(ip -o -4 address show dev "$interface_name" scope global | awk '{print $4; exit}')
if [ -z "$interface_cidr" ]; then
  echo "Unable to determine the primary interface CIDR" >&2
  exit 1
fi

docker compose exec -T api python -m app.cli ensure-primary-discovery-network "$interface_cidr"
