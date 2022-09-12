#!/usr/bin/env bats

load '/usr/local/lib/bats/load.bash'

# Uncomment the following line to debug stub failures
# export BUILDKITE_AGENT_STUB_DEBUG=/dev/tty

setup() {
  stub buildkite-agent "* : exit 0"
}

teardown() {
  unstub buildkite-agent
}

@test "trivy_os_cpu_string: uname failure" {
  stub uname "-a : exit 123"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 1 ]

  unstub uname
}

@test "trivy_os_cpu_string: unknown os" {
  stub uname "-a : echo foobar"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 2 ]

  unstub uname
}

@test "trivy_os_cpu_string: unknown cpu" {
  stub uname "-a : echo Linux foobar"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 3 ]

  unstub uname
}

@test "download_trivy: curl failure" {
  stub uname "-a : echo FreeBSD amd64"
  stub curl "* : exit 66"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 41 ]

  unstub uname
  unstub curl
}

@test "download_trivy: no hashes" {
  stub uname "-a : echo FreeBSD amd64"
  stub curl "* : echo ''"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 42 ]

  unstub uname
  unstub curl
}

@test "download_trivy: no matching hash" {
  stub uname "-a : echo FreeBSD amd64"
  stub curl "* : printf '%s\n%s\n' 'foo foo' 'bar bar'"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 43 ]

  unstub uname
  unstub curl
}

