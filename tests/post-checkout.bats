#!/usr/bin/env bats

setup() {
  load "$BATS_PLUGIN_PATH/load.bash"
}

@test "fs scan of a test app" {

  stub docker "run --rm -v $PWD/tests/testapp:/workdir  --rm aquasec/trivy:0.29.2 fs /workdir"

  run "$PWD/hooks/post-checkout"

  assert_success
  assert_output --partial "scanning filesystem"
}

@test "fs scan of a test app with exit-code=1" {
  export BUILDKITE_PLUGIN_TRIVY_EXIT_CODE=1

  stub docker "run --rm -v $PWD/tests/testapp:/workdir  --rm aquasec/trivy:0.29.2 fs --exit-code $BUILDKITE_PLUGIN_TRIVY_EXIT_CODE /workdir"

  run "$PWD/hooks/post-checkout"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "using exit-code=1 option while scanning"
}

@test "fs scan of a test app with exit-code=0" {
  export BUILDKITE_PLUGIN_TRIVY_EXIT_CODE=0

  stub docker "run --rm -v $PWD/tests/testapp:/workdir  --rm aquasec/trivy:0.29.2 fs --exit-code $BUILDKITE_PLUGIN_TRIVY_EXIT_CODE /workdir"

  run "$PWD/hooks/post-checkout"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "using exit-code=0 option while scanning"
}

@test "fs scan of a test app with non-default severity type" {
  export BUILDKITE_PLUGIN_TRIVY_SEVERITY="CRITICAL"
  export BUILDKITE_PLUGIN_TRIVY_EXIT_CODE=1

  stub docker "run --rm -v $PWD/tests/testapp:/workdir  --rm aquasec/trivy:0.29.2 fs --severity $BUILDKITE_PLUGIN_TRIVY_SEVERITY --exit-code $BUILDKITE_PLUGIN_TRIVY_EXIT_CODE /workdir"

  run "$PWD/hooks/post-checkout"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "using non-default severity types"
}

@test "fs scan of a test app with non-default severity type and non-default exit-code options" {
  export BUILDKITE_PLUGIN_TRIVY_SEVERITY="CRITICAL"
  export BUILDKITE_PLUGIN_TRIVY_EXIT_CODE=1

  stub docker "run --rm -v $PWD/tests/testapp:/workdir  --rm aquasec/trivy:0.29.2 fs --severity $BUILDKITE_PLUGIN_TRIVY_SEVERITY --exit-code $BUILDKITE_PLUGIN_TRIVY_EXIT_CODE /workdir"

  run "$PWD/hooks/post-checkout"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "using non-default severity types"
  assert_output --partial "using exit-code=1 option while scanning"
}
