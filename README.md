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
      - trivy#v1.6.0: ~
```
Define `--exit-code` option as a plugin parameter in  `pipeline.yml` to fail the pipeline when there are vulnerabilities:

```yml
steps:
  - command: ls
    plugins:
      - trivy#v1.6.0:
	exit-code: 1
```

Define `--severity` option as a plugin parameter in  `pipeline.yml` to scan specific type of vulnerabilities:	
Below is an example for scanning `CRITICAL` vulnerabilities.

```yml
steps:
  - command: ls
    plugins:
      - trivy#v1.6.0:
	severity: "CRITICAL"
```
## Developing

Provide examples on how to modify and test, e.g.:

To run the tests:

```shell
docker-compose run --rm tests
```
