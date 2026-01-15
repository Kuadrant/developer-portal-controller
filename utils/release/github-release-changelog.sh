#!/usr/bin/env bash

if [[ -z "$GITHUB_TOKEN" ]]; then
  echo "GITHUB_TOKEN must be set"
  exit 1
fi

# Get previous tag (latest release)
previous_tag=$(curl -sL "https://api.github.com/repos/Kuadrant/developer-portal-controller/releases/latest" \
  -H "Accept: application/vnd.github+json" | jq -r '.tag_name // empty')

if [[ -z "$previous_tag" ]]; then
  echo "No previous release found, generating notes from scratch"
  previous_tag=""
fi

# Generate notes via API
if [[ -n "$previous_tag" ]]; then
  payload="{\"tag_name\": \"$RELEASE_TAG\", \"previous_tag_name\": \"$previous_tag\"}"
else
  payload="{\"tag_name\": \"$RELEASE_TAG\"}"
fi

body=$(curl -sL "https://api.github.com/repos/Kuadrant/developer-portal-controller/releases/generate-notes" \
  -X POST \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -d "$payload" | jq -r '.body')

# Export to GitHub Actions environment
echo "releaseBody<<EOF" >> $GITHUB_ENV
echo "$body" >> $GITHUB_ENV
echo "EOF" >> $GITHUB_ENV
