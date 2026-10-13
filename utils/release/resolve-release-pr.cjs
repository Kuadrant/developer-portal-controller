module.exports = async ({ github, context, core, prNumber }) => {
  if (!/^[1-9][0-9]*$/.test(String(prNumber))) {
    throw new Error('A release PR number is required');
  }
  const repo = context.repo;
  const { data: pr } = await github.rest.pulls.get({ ...repo, pull_number: Number(prNumber) });
  if (!pr.merged || pr.state !== 'closed' || pr.base.repo.full_name.toLowerCase() !== `${repo.owner}/${repo.repo}`.toLowerCase()) {
    throw new Error('The release PR must be merged into this repository');
  }
  if (!/^release-v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(pr.base.ref)) {
    throw new Error('The release PR must target a release-X.Y branch');
  }
  if (!/^[a-f0-9]{40}$/.test(pr.merge_commit_sha)) {
    throw new Error('The release PR has no valid merge commit');
  }
  const { data: ref } = await github.rest.git.getRef({ ...repo, ref: `heads/${pr.base.ref}` });
  if (ref.object.sha !== pr.merge_commit_sha) {
    throw new Error('The release branch has advanced beyond the release PR');
  }
  core.setOutput('branch', pr.base.ref);
  core.setOutput('sha', pr.merge_commit_sha);
};
