# trivy buildkite plugin

The trivy buildkite plugin provides a convenient mechanism for running the
open-source trivy static analysis tool on your project. For more information
about trivy, please refer to their
[documentation](https://aquasecurity.github.io/trivy/latest/docs/).

## Features

- Automatically downloads and verifies the trivy executable if it cannot be
  found in the `PATH` environment variable's directories
- Executes a `filesystem` scan on the git repo cloned by buildkite. Refer to the
  [filesystem scan documentation](https://aquasecurity.github.io/trivy/latest/docs/vulnerability/scanning/filesystem/)
  for more information
- Executes an `image` scan against an existing Docker image ref. Refer to the
  [image scan documentation](https://aquasecurity.github.io/trivy/latest/docs/vulnerability/scanning/image/)
  for more information

## Basic example

The following code snippet demonstrates how to use the plugin in a pipeline step
with the default plugin configuration parameters:

```yml
steps:
  - command: ls
    plugins:
      - equinixmetal-buildkite/trivy#v1.20.0:
```

## Additional examples

Specify the `exit-code` option as a plugin parameter in `pipeline.yml` to fail
the pipeline when there are vulnerabilities:

```yml
steps:
  - command: ls
    plugins:
      - equinixmetal-buildkite/trivy#v1.20.0:
          exit-code: 1
```

Specify the `severity` option as a plugin parameter in `pipeline.yml` to scan
specific type of vulnerabilities. Below is an example for scanning `CRITICAL`
vulnerabilities:

```yml
steps:
  - command: ls
    plugins:
      - equinixmetal-buildkite/trivy#v1.20.0:
          severity: "CRITICAL"
```

Specify the `ignorefile` option as a plugin parameter in `pipeline.yml` to use
`.trivyignore.yaml` file

```yml
steps:
  - command: ls
    plugins:
      - equinixmetal-buildkite/trivy#v1.20.0:
          ignorefile: ".trivyignore.yaml"
```

$ cat .trivyignore.yaml
```yml
vulnerabilities:
  - id: CVE-2022-40897
    paths:
      - "usr/local/lib/python3.9/site-packages/setuptools-58.1.0.dist-info/METADATA"
    statement: Accept the risk
  - id: CVE-2023-2650
  - id: CVE-2023-3446
  - id: CVE-2023-3817
    purls:
      - "pkg:deb/debian/libssl1.1"
  - id: CVE-2023-29491
    expired_at: 2023-09-01

misconfigurations:
  - id: AVD-DS-0001
  - id: AVD-DS-0002
    paths:
      - "docs/Dockerfile"
    statement: The image needs root privileges

secrets:
  - id: aws-access-key-id
  - id: aws-secret-access-key
    paths:
      - "foo/bar/aws.secret"

licenses:
  - id: GPL-3.0 # License name is used as ID
    paths:
      - "usr/share/gcc/python/libstdcxx/v6/__init__.py"

```

## Configuration

### `exit-code` (Optional, integer)

Controls whether the security scan is blocking or not. This is done by setting
the exit code of the plugin. If the exit code is set to 0, the pipeline will
continue. If the exit code is set to 1, the pipeline will fail. (Defaults to 0)

### `timeout` (Optional, string)

Controls the maximum amount of time a scan will run for by passing the
`--timeout` argument to trivy.

### `severity` (Optional, string)

Controls the severity of the vulnerabilities to be scanned. (Defaults to
"UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")

### `ignore-unfixed` (Optional, boolean)

Controls whether to display only fixed vulnerabilities. (Defaults to false)

### `security-checks` (Optional, string) (DEPRECATED)

Controls the security checks to be performed. This option is deprecated and may
be removed in the future. Use `scanners` instead. (Defaults to "vuln,misconfig")

### `scanners` (Optional, string)

Controls the security scanners to be used. This replaced security-checks
(Defaults to "vuln,misconfig")

### `ignorefile` (Optional, string) (EXPERIMENTAL)

Controls the security checks to be ignored as specified in a YAML file.
Note: This trivy feature is experimental and might change in the future.

### `skip-files` (Optional, string)

Controls the files to be skipped during the scan. (Defaults to "")

### `skip-dirs` (Optional, string)

Controls the directories to be skipped during the scan. (Defaults to "")

### `image-ref` (Optional, string)

**Important**: Please ensure the target Docker image is built prior to the trivy
plugin running when using this option. The trivy plugin does not build Docker
images; it only scans existing images.

Controls the image reference to be scanned. If no image is specified, the image
scanning step is skipped. This is also able to infer the image from the
[`docker-metadata` plugin](https://github.com/equinixmetal-buildkite/docker-metadata-buidkite-plugin).
(Defaults to "")

### `trivy-version` (Optional, string)

Controls the version of trivy to be used.

### `helm-overrides-file` (Optional, string)

To pass helm override values to trivy config scan

### `debug` (Optional, boolean)

Enable debug flag for trivy.

### `kube-version` (Optional, string)

Sets the `helm-kube-version` passed to trivy.

## Developing

To run the tests:

```shell
make test
```

Run the tests with debug logging enabled:

```shell
TEST_DEBUG=1 make test
```

To enable debug logging for a stubbed command in the test, you need to set or
uncomment the export for the necessary command in the `.bats` file.

e.g. to view the debug logging for the `trivy` command, set the following at the
top of the `.bats` file:

```shell
export TRIVY_STUB_DEBUG=/dev/tty
```

and then run the tests with debug logging enabled:

```shell
TEST_DEBUG=1 make test
```
