#!/usr/bin/env bats

load '/usr/local/lib/bats/load.bash'

export TRIVY_EXE_PATH="$(mktemp)"

# Uncomment the following line to debug stub failures
# export BUILDKITE_AGENT_STUB_DEBUG=/dev/tty

@test "fs scan of a test app" {
  # TODO(jaosorior): Change the exit code if we change the default
  stub trivy "fs --exit-code 0 --security-checks vuln,config . : echo fs scan success"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"No container image was scanned due to a lack of an image reference. This is fine.<br />\" --context trivy-container-scan : echo no image scan happened" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "fs scan success"
  assert_output --partial "no image scan happened"

  unstub trivy
  unstub buildkite-agent
}

@test "fs scan of a test app with exit-code=1" {
  export BUILDKITE_PLUGIN_TRIVY_EXIT_CODE=1

  stub trivy "fs --exit-code 1 --security-checks vuln,config . : echo fs scan success"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"No container image was scanned due to a lack of an image reference. This is fine.<br />\" --context trivy-container-scan : echo no image scan happened" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "fs scan success"
  assert_output --partial "using exit-code=1 option while scanning"

  unstub trivy
  unstub buildkite-agent
}

@test "fs scan of a test app with exit-code=0" {
  export BUILDKITE_PLUGIN_TRIVY_EXIT_CODE=0

  stub trivy "fs --exit-code 0 --security-checks vuln,config . : echo fs scan success"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"No container image was scanned due to a lack of an image reference. This is fine.<br />\" --context trivy-container-scan : echo no image scan happened" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "fs scan success"
  assert_output --partial "using exit-code=0 option while scanning"

  unstub trivy
  unstub buildkite-agent
}

@test "fs scan of a test app with exit-code=1 with actual failure" {
  export BUILDKITE_PLUGIN_TRIVY_EXIT_CODE=1

  stub trivy "fs --exit-code 1 --security-checks vuln,config . : exit 1"
  stub buildkite-agent "annotate --style error \"trivy found vulnerabilities in repository. See the job output for details.<br />\" --context trivy-fs-scan : echo fs scan failure" \
    "annotate --style success \"No container image was scanned due to a lack of an image reference. This is fine.<br />\" --context trivy-container-scan : echo no image scan happened" \

  run "$PWD/hooks/post-command"

  assert_failure
  assert_output --partial "scanning filesystem"
  assert_output --partial "fs scan failure"
  assert_output --partial "using exit-code=1 option while scanning"

  unstub trivy
  unstub buildkite-agent
}

@test "fs scan of test app with ignore-unfixed flag set" {
  export BUILDKITE_PLUGIN_TRIVY_IGNORE_UNFIXED=true

  stub trivy "fs --exit-code 0 --ignore-unfixed --security-checks vuln,config . : echo fs scan success with --ignore-unfixed"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo output success" \
    "annotate --style success \"No container image was scanned due to a lack of an image reference. This is fine.<br />\" --context trivy-container-scan : echo no image scan happened" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "fs scan success with --ignore-unfixed"
  assert_output --partial "ignore-unfixed is set. Will ignore unfixed vulnerabilities"
  assert_output --partial "output success"

  unstub trivy
  unstub buildkite-agent
}

@test "fs scan of a test app with non-default severity type CRITICAL" {
  export BUILDKITE_PLUGIN_TRIVY_SEVERITY="CRITICAL"
  export BUILDKITE_PLUGIN_TRIVY_EXIT_CODE=1

  stub trivy "fs --exit-code 1 --severity $BUILDKITE_PLUGIN_TRIVY_SEVERITY --security-checks vuln,config . : echo fs scan success"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"No container image was scanned due to a lack of an image reference. This is fine.<br />\" --context trivy-container-scan : echo no image scan happened" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "using non-default severity types"

  unstub trivy
  unstub buildkite-agent
}

@test "fs scan of a test app with non-default severity type CRITICAL and HIGH" {
  export BUILDKITE_PLUGIN_TRIVY_SEVERITY="CRITICAL,HIGH"
  export BUILDKITE_PLUGIN_TRIVY_EXIT_CODE=1

  stub trivy "fs --exit-code 1 --severity $BUILDKITE_PLUGIN_TRIVY_SEVERITY --security-checks vuln,config . : echo fs scan success"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"No container image was scanned due to a lack of an image reference. This is fine.<br />\" --context trivy-container-scan : echo no image scan happened" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "using non-default severity types"

  unstub trivy
  unstub buildkite-agent
}

@test "fs scan of a test app with non-default severity type CRITICAL,HIGH and MEDIUM" {
  export BUILDKITE_PLUGIN_TRIVY_SEVERITY="CRITICAL,HIGH,MEDIUM"
  export BUILDKITE_PLUGIN_TRIVY_EXIT_CODE=1

  stub trivy "fs --exit-code 1 --severity $BUILDKITE_PLUGIN_TRIVY_SEVERITY --security-checks vuln,config . : echo fs scan success"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"No container image was scanned due to a lack of an image reference. This is fine.<br />\" --context trivy-container-scan : echo no image scan happened" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "using non-default severity types"

  unstub trivy
  unstub buildkite-agent
}

@test "fs scan of a test app with only vulnerbility security check" {
  export BUILDKITE_PLUGIN_TRIVY_SECURITY_CHECKS="vuln"
  stub trivy "fs --exit-code 0 --security-checks $BUILDKITE_PLUGIN_TRIVY_SECURITY_CHECKS . : echo fs scan success"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"No container image was scanned due to a lack of an image reference. This is fine.<br />\" --context trivy-container-scan : echo no image scan happened" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "using $BUILDKITE_PLUGIN_TRIVY_SECURITY_CHECKS security checks"

  unstub trivy
  unstub buildkite-agent
}

@test "fs scan of a test app with vulnerbility and configuration security check" {
  export BUILDKITE_PLUGIN_TRIVY_SECURITY_CHECKS="vuln,config"
  stub trivy "fs --exit-code 0 --security-checks $BUILDKITE_PLUGIN_TRIVY_SECURITY_CHECKS . : echo fs scan success"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"No container image was scanned due to a lack of an image reference. This is fine.<br />\" --context trivy-container-scan : echo no image scan happened" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "using $BUILDKITE_PLUGIN_TRIVY_SECURITY_CHECKS security checks"

  unstub trivy
  unstub buildkite-agent
}

@test "fs scan of a test app with vulnerbility,secret and configuration security check" {
  export BUILDKITE_PLUGIN_TRIVY_SECURITY_CHECKS="vuln,secret,config"
  stub trivy "fs --exit-code 0 --security-checks $BUILDKITE_PLUGIN_TRIVY_SECURITY_CHECKS . : echo fs scan success"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"No container image was scanned due to a lack of an image reference. This is fine.<br />\" --context trivy-container-scan : echo no image scan happened" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning filesystem"
  assert_output --partial "using $BUILDKITE_PLUGIN_TRIVY_SECURITY_CHECKS security checks"

  unstub trivy
  unstub buildkite-agent
}

@test "scan of image reference not present locally" {
  export BUILDKITE_PLUGIN_TRIVY_IMAGE_REF="nginx:latest"

  stub trivy \
    "fs --exit-code 0 --security-checks vuln,config . : echo fs scan success" \
    "image --exit-code 0 $BUILDKITE_PLUGIN_TRIVY_IMAGE_REF : echo container image scan success"
  stub docker \
    "images -q $BUILDKITE_PLUGIN_TRIVY_IMAGE_REF : echo ''" \
    "pull $BUILDKITE_PLUGIN_TRIVY_IMAGE_REF : echo 'pulled image'"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"trivy didn't find any relevant vulnerabilities in the container image<br />\" --context trivy-container-scan : echo container image scan success" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning container image"
  assert_output --partial "pulled image"
  assert_output --partial "container image scan success"

  unstub trivy
  unstub docker
  unstub buildkite-agent
}

@test "scan of image reference present locally" {
  export BUILDKITE_PLUGIN_TRIVY_IMAGE_REF="nginx:latest"

  stub trivy \
    "fs --exit-code 0 --security-checks vuln,config . : echo fs scan success" \
    "image --exit-code 0 $BUILDKITE_PLUGIN_TRIVY_IMAGE_REF : echo container image scan success"
  stub docker \
    "images -q $BUILDKITE_PLUGIN_TRIVY_IMAGE_REF : echo 'Found image!'"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"trivy didn't find any relevant vulnerabilities in the container image<br />\" --context trivy-container-scan : echo container image scan success" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning container image"
  assert_output --partial "image '$BUILDKITE_PLUGIN_TRIVY_IMAGE_REF' already present locally"
  assert_output --partial "container image scan success"

  unstub trivy
  unstub docker
  unstub buildkite-agent
}

@test "scan of image not present locally fails" {
  export BUILDKITE_PLUGIN_TRIVY_IMAGE_REF="nginx:latest"

  stub trivy \
    "fs --exit-code 0 --security-checks vuln,config . : echo fs scan success" \
    "image --exit-code 0 $BUILDKITE_PLUGIN_TRIVY_IMAGE_REF : exit 1"
  stub docker \
    "images -q $BUILDKITE_PLUGIN_TRIVY_IMAGE_REF : echo ''" \
    "pull $BUILDKITE_PLUGIN_TRIVY_IMAGE_REF : echo 'pulled image'"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style error \"trivy found vulnerabilities in the container image. See the job output for details.<br />\" --context trivy-container-scan : echo container image scan failure" \

  run "$PWD/hooks/post-command"

  assert_failure
  assert_output --partial "scanning container image"
  assert_output --partial "pulled image"
  assert_output --partial "fs scan success"
  assert_output --partial "container image scan failure"

  unstub trivy
  unstub docker
  unstub buildkite-agent
}

@test "scan image from docker-metadata present locally" {
  export DOCKER_METADATA_DIR="$(mktemp -d)"
  touch "$DOCKER_METADATA_DIR/tags"
  _TAGS_0="foo/bar:baz"
  echo "$_TAGS_0" >> "$DOCKER_METADATA_DIR/tags"

  stub trivy \
    "fs --exit-code 0 --security-checks vuln,config . : echo fs scan success" \
    "image --exit-code 0 $_TAGS_0 : echo container image scan success"
  stub docker \
    "images -q $_TAGS_0 : echo 'Found image!'"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"trivy didn't find any relevant vulnerabilities in the container image<br />\" --context trivy-container-scan : echo container image scan success" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning container image"
  assert_output --partial "image '$_TAGS_0' already present locally"
  assert_output --partial "container image scan success"

  unstub trivy
  unstub docker
  unstub buildkite-agent
}

@test "scan image from docker-metadata not present locally" {
  export DOCKER_METADATA_DIR="$(mktemp -d)"
  touch "$DOCKER_METADATA_DIR/tags"
  _TAGS_0="foo/bar:baz"
  echo "$_TAGS_0" >> "$DOCKER_METADATA_DIR/tags"

  stub trivy \
    "fs --exit-code 0 --security-checks vuln,config . : echo fs scan success" \
    "image --exit-code 0 $_TAGS_0 : echo container image scan success"
  stub docker \
    "images -q $_TAGS_0 : echo ''" \
    "pull $_TAGS_0 : echo 'pulled image'"
  stub buildkite-agent "annotate --style success \"trivy didn't find any relevant vulnerabilities in the repository<br />\" --context trivy-fs-scan : echo fs scan success" \
    "annotate --style success \"trivy didn't find any relevant vulnerabilities in the container image<br />\" --context trivy-container-scan : echo container image scan success" \

  run "$PWD/hooks/post-command"

  assert_success
  assert_output --partial "scanning container image"
  assert_output --partial "pulled image"
  assert_output --partial "container image scan success"

  unstub trivy
  unstub docker
  unstub buildkite-agent
}
