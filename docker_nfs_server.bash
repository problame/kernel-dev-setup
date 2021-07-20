#!/usr/bin/env bash
# Copyright (C) 2020-2021 Christian Schwarz  - All Rights Reserved.
set -euo pipefail

set -x

listen_ip="$1"
shift
vm="$1"
shift
paths=("$@")

exports="$(mktemp -t docker_nfs_server.exports.XXXXXX)"
volargs=()
for p in "${paths[@]}"; do
    stat "$p" || (echo "$p must exist on the host"; exit 1)
    volargs+=("-v$p:/host/$p")
    cat >> "$exports" <<EOF
/host/$p	$vm(rw,no_subtree_check,no_root_squash,insecure)
EOF

done

cat "$exports"

exec docker run -it                                     \
  "${volargs[@]}" \
  -v "$exports":/etc/exports:ro \
  --cap-add SYS_ADMIN                                 \
  --network=host \
  -p "$listen_ip:2049":2049                                        \
  -p "$listen_ip:111":111 \
  -p "$listen_ip:32765":32765 \
  -p "$listen_ip:32767":32767\
  erichough/nfs-server

