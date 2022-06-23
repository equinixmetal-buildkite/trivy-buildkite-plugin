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
      - hnadimin/trivy#v1.0.0: ~
```

## Developing

Provide examples on how to modify and test, e.g.:

To run the tests:

```shell
docker-compose run --rm tests
```
