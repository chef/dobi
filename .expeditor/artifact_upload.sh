#!/bin/bash

set -eou pipefail

version=$(cat VERSION)

# this will ideally be a directory we export as an env var when processing the config
workdir="/workdir/dist"

echo "--- Uploading binaries to Artifactory"

for file in ${workdir}/**/*
do
  dir_path=$(dirname "${file}")
  binary=$(basename "${file}")

  # get the last part of the dir path to strip the OS and ARCH
  # ex: <binary>_<os>_<arch>
  IFS='_' read -r -a parts <<< "$(basename "${dir_path}")"
  util_name=${parts[0]}
  os=${parts[1]}
  arch=${parts[2]}

  jfrog rt u \
  --apikey="${ARTIFACTORY_TOKEN}" \
  --url=https://artifactory.chef.co/artifactory \
  --target-props "project=${util_name};version=${version};os=${os};arch=${arch}" \
  "${file}" \
  "go-binaries-local/${util_name}/${version}/${os}/${arch}/${binary}"
done