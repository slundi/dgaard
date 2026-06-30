#!/usr/bin/env bash
# codeberg-publish.sh — mirror a GitHub release to Codeberg.
#
# Called from the release workflows after `softprops/action-gh-release` has
# created the GitHub release. Reads artifacts from the current working
# directory (downloaded by actions/download-artifact in the workflow).
#
# Required environment:
#   CODEBERG_TOKEN  Codeberg access token with `write:repository` scope.
#   TAG             Release tag, e.g. dgaard-v1.2.3
#   NAME            Human-readable release name, e.g. "dgaard v1.2.3"
#
# Optional:
#   CODEBERG_REPO   Defaults to slundi/dgaard.
#
# Assumes the git tag has already been pushed to Codeberg (typical when the
# repo is mirrored bidirectionally). If the tag is missing on Codeberg the
# Forgejo API will fail to create the release — push the tag first.

set -euo pipefail

: "${CODEBERG_TOKEN:?CODEBERG_TOKEN must be set}"
: "${TAG:?TAG must be set (e.g. dgaard-v1.2.3)}"
: "${NAME:?NAME must be set (e.g. \"dgaard v1.2.3\")}"

REPO="${CODEBERG_REPO:-slundi/dgaard}"
API="https://codeberg.org/api/v1/repos/${REPO}"
AUTH_HEADER="Authorization: token ${CODEBERG_TOKEN}"

tmp_body="$(mktemp)"
trap 'rm -f "${tmp_body}"' EXIT

echo "Creating Codeberg release ${TAG} on ${REPO}..."
payload="$(jq -nc --arg tag "$TAG" --arg name "$NAME" \
  '{tag_name:$tag, name:$name, draft:false, prerelease:false}')"

status="$(curl -sS -o "${tmp_body}" -w '%{http_code}' \
  -H "${AUTH_HEADER}" -H 'Content-Type: application/json' \
  -X POST "${API}/releases" -d "${payload}")"

case "$status" in
  201)
    release_id="$(jq -r '.id' < "${tmp_body}")"
    ;;
  409)
    echo "Release ${TAG} already exists on Codeberg, fetching id..."
    release_id="$(curl -fsSL -H "${AUTH_HEADER}" "${API}/releases/tags/${TAG}" | jq -r '.id')"
    ;;
  *)
    echo "Failed to create Codeberg release (HTTP ${status}):" >&2
    cat "${tmp_body}" >&2
    exit 1
    ;;
esac

if [ -z "${release_id}" ] || [ "${release_id}" = "null" ]; then
  echo "Could not determine Codeberg release id" >&2
  exit 1
fi
echo "Codeberg release id: ${release_id}"

shopt -s nullglob
uploaded=0
for asset in *.tar.gz *.zip; do
  echo "  uploading ${asset}..."
  curl -fsSL -H "${AUTH_HEADER}" \
    -X POST "${API}/releases/${release_id}/assets?name=$(basename "${asset}")" \
    -F "attachment=@${asset}" >/dev/null
  uploaded=$((uploaded + 1))
done

if [ "${uploaded}" -eq 0 ]; then
  echo "codeberg-publish.sh: no artifacts found in $(pwd) (expected *.tar.gz / *.zip)" >&2
  exit 1
fi
echo "Mirrored ${uploaded} asset(s) to Codeberg release ${TAG}."
