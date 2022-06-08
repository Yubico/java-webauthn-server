#!/bin/bash

make-contents() {
  cat << EOF
## Mutation test results

Package | Coverage | Stats | Prev | Prev |
------- | --------:|:-----:| ----:|:----:|
EOF

  jq -s '.[0] as $old | .[1] as $new
    | {
      packages: (
        $old | keys
        | map({
            ("`\(.)`"): {
              before: {
                detected: $old[.].detected,
                mutations: $old[.].mutations,
              },
              after: {
                detected: $new[.].detected,
                mutations: $new[.].mutations,
              },
              percentage_diff: (($new[.].detected / $new[.].mutations - $old[.].detected / $old[.].mutations) * 100 | round),
            },
          })
        | add
      ),
      overall: {
        before: {
          detected: [($old[] | .detected)] | add,
          mutations: [($old[] | .mutations)] | add,
        },
        after: {
          detected: [($new[] | .detected)] | add,
          mutations: [($new[] | .mutations)] | add,
        },
        percentage_diff: (
          (
            ([($new[] | .detected)] | add) / ([($new[] | .mutations)] | add)
            - ([($old[] | .detected)] | add) / ([($old[] | .mutations)] | add)
          ) * 100 | round
        ),
      },
    }
    | { ("**Overall**"): .overall } + .packages
    | to_entries
    | .[]
    | def difficon:
        if .after.detected == .after.mutations then ":trophy:"
        elif .percentage_diff > 0 then ":green_circle:"
        elif .percentage_diff < 0 then ":small_red_triangle_down:"
        else ":small_blue_diamond:"
        end;
      def triangles:
        if . > 0 then ":small_red_triangle:"
        elif . < 0 then ":small_red_triangle_down:"
        else ":small_blue_diamond:"
        end;
      "\(.key) | **\(.value.after.detected / .value.after.mutations * 100 | floor) %** \(.value | difficon) | \(.value.after.detected) \(.value.after.detected - .value.before.detected | triangles) / \(.value.after.mutations) \(.value.after.mutations - .value.before.mutations | triangles)| \(.value.before.detected / .value.before.mutations * 100 | floor) % | \(.value.before.detected) / \(.value.before.mutations)"
  ' \
    "${1}" "${2}" --raw-output

  if [[ -n "${3}" ]]; then
    cat << EOF

Previous run: ${3}
EOF
  fi

}

make-contents "$@" | python -c 'import json; import sys; print(json.dumps({"body": sys.stdin.read()}))'
