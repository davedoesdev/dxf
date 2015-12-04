#!/bin/bash
case "$(docker inspect '--format={{.State.Running}}' "$1" 2> /dev/null)" in
  true)
    docker stop "$1" > /dev/null
esac
if docker inspect '--format={{.Id}}' "$1" >& /dev/null; then
  docker rm -v "$1" > /dev/null
fi
