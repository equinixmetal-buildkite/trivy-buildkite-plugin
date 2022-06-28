#!/usr/bin/env bats

setup() {
  load "$BATS_PLUGIN_PATH/load.bash"
}

@test "fs scan of a test app" {

  stub docker "run --rm -v $PWD/tests/testapp:/workdir  --rm aquasec/trivy:0.29.2 fs /workdir"

  run "$PWD/hooks/post-checkout"

 # assert_output --partial "Detecting pip vulnerabilities..."
 # assert_output --partial "HIGH: 2"
  assert_success
  unstub docker
}
