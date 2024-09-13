#!/bin/bash
set -exuo pipefail

ARTIFACT_PATH="/artifacts/${CI_PROJECT_NAME}/${CI_COMMIT_REF}/*.deb"
RELEASE_ARTIFACT_DIR="${RELEASE_ARTIFACT_DIR:-"$(dirname $0)/../../../../release-artifacts"}"

if [[ -d "$RELEASE_ARTIFACT_DIR" ]]; then
  rsync -vP $ARTIFACT_PATH $RELEASE_ARTIFACT_DIR
else
  RSYNC_HOST=${RSYNC_HOST:-"taler.host.internal"}
  RSYNC_PORT=${RSYNC_PORT:-424242}
  RSYNC_PATH=${RSYNC_PATH:-"incoming_packages/bookworm-taler-ci/"}
  RSYNC_DEST=${RSYNC_DEST:-"rsync://${RSYNC_HOST}/${RSYNC_PATH}"}

  rsync -vP \
    --port ${RSYNC_PORT} \
    ${ARTIFACT_PATH} ${RSYNC_DEST}
fi;
