#!/bin/bash

default_version="0.29.2"
version="${BUILDKITE_PLUGIN_TRIVY_VERSION:-$default_version}"
image="aquasec/trivy:${version}"