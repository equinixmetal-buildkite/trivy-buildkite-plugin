<dev align="centre">
<img src="buildkiteplugin.png" width="600">
</div>


# Buildkite Plugin Template

Check the [buildkite organization](https://github.com/buildkite-plugins) or [website](https://buildkite.com/plugins) to see if your plugin already exists or we can contribute to it !

Be sure to update this readme with your plugin information after using the template repository.

## Example

Provide an example of using this plugin, like so:

Add the following to your `pipeline.yml`:

```yml
steps:
  - command: ls
    plugins:
      - equinixmetal-buildkite/trivy#v1.14.2: ~
```
Define `--exit-code` option as a plugin parameter in  `pipeline.yml` to fail the pipeline when there are vulnerabilities:

```yml
steps:
  - command: ls
    plugins:
      - equinixmetal-buildkite/trivy#v1.14.2:
        exit-code: 1
```

Define `--severity` option as a plugin parameter in  `pipeline.yml` to scan specific type of vulnerabilities:	
Below is an example for scanning `CRITICAL` vulnerabilities.

```yml
steps:
  - command: ls
    plugins:
      - equinixmetal-buildkite/trivy#v1.14.2:
        severity: "CRITICAL"
```

## Configuration

### `exit-code` (Optional, array)

Controls whether the security scan is blocking or not. This is done by setting the exit code of the plugin. If the exit code is set to 0, the pipeline will continue. If the exit code is set to 1, the pipeline will fail. (Defaults to 0)

### `severity` (Optional, string)

Controls the severity of the vulnerabilities to be scanned. (Defaults to "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL")

### `ignore-unfixed` (Optional, boolean)

Controls whether to display only fixed vulnerabilities. (Defaults to false)

### `security-checks` (Optional, string)

Controls the security checks to be performed. (Defaults to "vuln,config")

### `image-ref` (Optional, string)

Controls the image reference to be scanned. If no image is specified the image scanning step is skipped. This is also able to infer the image from the [`docker-metadata` plugin](https://github.com/equinixmetal-buildkite/docker-metadata-buidkite-plugin), but one needs to ensure that the images are built
before calling the `trivy` plugin. (Defaults to "")

### `trivy-version` (Optional, string)

Controls the version of trivy to be used.

## Developing

Provide examples on how to modify and test, e.g.:

To run the tests:

```shell
make test
```
