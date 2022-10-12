#!/bin/bash

xq '.mutations.mutation
  | group_by(.mutatedClass | split(".") | .[:-1])
  | INDEX(.[0].mutatedClass | split(".") | .[:-1] | join("."))
  | map_values({
      detected: (map(select(.["@detected"] == "true")) | length),
      mutations: length,
    })
' "${1}"
