#!/usr/bin/env bats

load '/usr/local/lib/bats/load.bash'

# Uncomment the following line to debug stub failures
# export BUILDKITE_AGENT_STUB_DEBUG=/dev/tty

readonly TESTV='6.6.6'

setup() {
  export BUILDKITE_PLUGIN_TRIVY_VERSION="${TESTV}"
  stub buildkite-agent "* : exit 0"
}

teardown() {
  unset BUILDKITE_PLUGIN_TRIVY_VERSION
  # Handle scenarios where the stub is never called by returning 0.
  # This is because unstub throws an error if the stub was never
  # executed. We need to do so because there are scenarios where
  # buildkite-agent is never called.
  unstub buildkite-agent || return 0
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

@test "download_trivy: curl hashes file failure" {
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

@test "download_trivy: mktemp failure" {
  stub uname "-a : echo FreeBSD amd64"
  stub curl "--fail -L https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_checksums.txt : echo '82678d08fe942e81f8bb72a13e70bc3696f9a69756bdb2ee507e0f57cb5b3777  trivy_${TESTV}_FreeBSD-64bit.tar.gz'"
  stub mktemp "* : exit 123"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 44 ]

  unstub uname
  unstub curl
  unstub mktemp
}

@test "download_trivy: curl trivy exectuable failure" {
  stub uname "-a : echo FreeBSD amd64"
  stub mktemp "-d : echo /tmp/x"
  stub curl \
    "--fail -L https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_checksums.txt : echo 'aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f  trivy_${TESTV}_FreeBSD-64bit.tar.gz'" \
    "--fail -L -o /tmp/x/temp-trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_FreeBSD-64bit.tar.gz : exit 123"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 45 ]

  unstub uname
  unstub mktemp
  unstub curl
}

@test "sha2_256_hash_file: target file missing" {
  stub uname "-a : echo FreeBSD amd64"
  stub mktemp "-d : echo /tmp/x"
  stub curl \
    "--fail -L https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_checksums.txt : echo 'AAAA  trivy_${TESTV}_FreeBSD-64bit.tar.gz'" \
    "--fail -L -o /tmp/x/temp-trivy.tar.gz https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_FreeBSD-64bit.tar.gz : echo foobar"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 31 ]

  unstub uname
  unstub mktemp
  unstub curl
}

@test "sha2_256_hash_file: empty hash result" {
  temp="$(mktemp -d)"
  tar_file="${temp}/temp-trivy.tar.gz"

  stub uname "-a : echo FreeBSD amd64"
  stub mktemp "-d : echo ${temp}"
  stub curl \
    "--fail -L https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_checksums.txt : echo 'AAAA  trivy_${TESTV}_FreeBSD-64bit.tar.gz'" \
    "--fail -L -o ${tar_file} https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_FreeBSD-64bit.tar.gz : echo foobar > ${tar_file}"
  stub sha256sum "* : echo"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 34 ]

  unstub uname
  unstub curl
  unstub mktemp
  unstub sha256sum
}

@test "sha2_256_hash_file: hash verification failure" {
  temp="$(mktemp -d)"
  tar_file="${temp}/temp-trivy.tar.gz"

  stub uname "-a : echo FreeBSD amd64"
  stub mktemp "-d : echo ${temp}"
  stub curl \
    "--fail -L https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_checksums.txt : echo 'AAAA  trivy_${TESTV}_FreeBSD-64bit.tar.gz'" \
    "--fail -L -o ${tar_file} https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_FreeBSD-64bit.tar.gz : echo foobar > ${tar_file}"
  stub sha256sum "* : echo 'hailsatan  ${tar_file}'"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 35 ]

  unstub uname
  unstub curl
  unstub mktemp
  unstub sha256sum
}

@test "download_trivy: un-tar failure" {
  temp="$(mktemp -d)"
  tar_file="${temp}/temp-trivy.tar.gz"

  stub uname "-a : echo FreeBSD amd64"
  stub mktemp "-d : echo ${temp}"
  stub curl \
    "--fail -L https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_checksums.txt : echo 'AAAA  trivy_${TESTV}_FreeBSD-64bit.tar.gz'" \
    "--fail -L -o ${tar_file} https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_FreeBSD-64bit.tar.gz : echo foobar > ${tar_file}"
  stub sha256sum "* : echo 'AAAA  ${tar_file}'"
  stub tar "* : exit 123"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 46 ]

  unstub uname
  unstub curl
  unstub mktemp
  unstub sha256sum
  unstub tar
}

@test "download_trivy: trivy missing from tar file" {
  temp="$(mktemp -d)"
  tar_file="${temp}/temp-trivy.tar.gz"

  stub uname "-a : echo FreeBSD amd64"
  stub mktemp "-d : echo ${temp}"
  stub curl \
    "--fail -L https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_checksums.txt : echo 'AAAA  trivy_${TESTV}_FreeBSD-64bit.tar.gz'" \
    "--fail -L -o ${tar_file} https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_FreeBSD-64bit.tar.gz : echo foobar > ${tar_file}"
  stub sha256sum "* : echo 'AAAA  ${tar_file}'"
  stub tar "* : exit 0"

  run "$PWD/hooks/pre-checkout"

  [ "$status" -eq 47 ]

  unstub uname
  unstub curl
  unstub mktemp
  unstub sha256sum
  unstub tar
}

@test "main: existing trivy" {
  temp="$(mktemp -d)"
  trivy_exe="${temp}/trivy"
  touch "${trivy_exe}"

  stub which "trivy : echo ${trivy_exe}"
  echo "${trivy_exe}"

  run "$PWD/hooks/pre-checkout"

  [ "$output" == "${trivy_exe}" ]

  unstub which
}

@test "main: trivy downloaded from internets to temp" {
  temp="$(mktemp -d)"
  tar_file="${temp}/temp-trivy.tar.gz"
  trivy_exe="${temp}/trivy"

  stub which \
    "trivy : exit 1" \
    "sha256sum : exit 0"
  stub uname "-a : echo FreeBSD amd64"
  stub mktemp "-d : echo ${temp}"
  stub curl \
    "--fail -L https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_checksums.txt : echo 'AAAA  trivy_${TESTV}_FreeBSD-64bit.tar.gz'" \
    "--fail -L -o ${tar_file} https://github.com/aquasecurity/trivy/releases/download/v${TESTV}/trivy_${TESTV}_FreeBSD-64bit.tar.gz : echo foobar > ${tar_file}"
  stub sha256sum "* : echo 'AAAA  ${tar_file}'"
  stub tar "* : touch ${trivy_exe}"

  run "$PWD/hooks/pre-checkout"

  [ "$output" == "${trivy_exe}" ]

  unstub which
  unstub uname
  unstub curl
  unstub mktemp
  unstub sha256sum
  unstub tar
}
