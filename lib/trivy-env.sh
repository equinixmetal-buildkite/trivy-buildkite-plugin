#!/bin/bash

export default_version="0.29.2"
export version="${BUILDKITE_PLUGIN_TRIVY_VERSION:-$default_version}"
export image="aquasec/trivy:${version}"