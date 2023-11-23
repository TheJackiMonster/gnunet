#!/bin/bash
set -evuo pipefail

# Use podman if available, otherwise use docker.
# Fails if neither is found in PATH
OCI_RUNTIME=$(which podman || which docker)
REPO_NAME=$(basename "${PWD}")
JOB_NAME="${1}"
JOB_CONTAINER=$((grep CONTAINER_NAME ci/jobs/${JOB_NAME}/config.ini | cut -d' ' -f 3) || echo "${REPO_NAME}")

echo "${JOB_CONTAINER}"

if [ "${JOB_CONTAINER}" = "${REPO_NAME}" ] ; then
	"${OCI_RUNTIME}" build \
		-t "${JOB_CONTAINER}" \
		-f ci/Containerfile .
fi

"${OCI_RUNTIME}" run \
	--rm \
	-ti \
	--env CI_COMMIT_REF="$(git rev-parse HEAD)" \
	--volume "${PWD}":/workdir \
	--workdir /workdir \
	"${JOB_CONTAINER}" \
	ci/jobs/"${JOB_NAME}"/job.sh

top_dir=$(dirname "${BASH_SOURCE[0]}")

#"${top_dir}"/build.sh
