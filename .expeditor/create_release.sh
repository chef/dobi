#!/bin/bash
set -eou pipefail

version=$(cat VERSION)
art_token=$(vault kv get -field token account/static/artifactory/buildkite)
files=()

function download_artifacts {
  os=$1
  arch=$2

  echo "--- Artifactory download dobi binaries for ${os} ${arch}"
  jfrog rt dl \
  --apikey="${art_token}" \
  --url="https://artifactory.chef.co/artifactory" \
  --flat \
  --detailed-summary \
  --props "project=dobi;version=${version};os=${os};arch=${arch}" \
  "go-binaries-local/*" "go-binaries/${os}/${arch}/"

  for file in go-binaries/${os}/${arch}/*
  do
    if [[ ${os} == "windows" ]]; then
      util_name=$(basename -s ".exe" "${file}")

      zip -j "${util_name}_${os}_${arch}.zip" "${file}"
      files+=("${util_name}_${os}_${arch}.zip")
    else
      util_name=$(basename "${file}")

      tar -czf "${util_name}_${os}_${arch}.tar.gz" -C "go-binaries/${os}/${arch}" "${util_name}"
      files+=("${util_name}_${os}_${arch}.tar.gz")
    fi
  done
}

download_artifacts linux amd64
download_artifacts linux arm64
download_artifacts darwin amd64
download_artifacts darwin arm64
download_artifacts windows amd64

echo "--- GitHub publish release ${version}"
gh release create "${version}" "${files[@]}" -t "${version}"