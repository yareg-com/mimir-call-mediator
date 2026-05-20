#!/bin/sh
args=""

# Process PEER variables
i=1
while eval "[ -n \"\$PEER$i\" ]"; do
    eval "peer=\$PEER$i"
    args="$args -p $peer"
    i=$((i + 1))
done

exec mimir-call-mediator $args
