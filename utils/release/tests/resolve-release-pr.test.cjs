const { test } = require('node:test');
const assert = require('node:assert/strict');
const resolve = require('../resolve-release-pr.cjs');

function fixture() {
  const sha = 'a'.repeat(40);
  const pr = { merged: true, state: 'closed', base: { ref: 'release-0.3', repo: { full_name: 'Kuadrant/developer-portal-controller' } }, merge_commit_sha: sha };
  const outputs = {};
  const ref = { object: { sha } };
  const args = {
    prNumber: '99', context: { repo: { owner: 'Kuadrant', repo: 'developer-portal-controller' } },
    core: { setOutput: (key, value) => { outputs[key] = value; } },
    github: { rest: { pulls: { get: async () => ({ data: pr }) }, git: { getRef: async () => ({ data: ref }) } } },
  };
  return { pr, ref, outputs, args };
}

for (const branch of ['release-0.3', 'release-v0.3']) {
  test(`resolves merged PR at ${branch} tip`, async () => {
    const f = fixture(); f.pr.base.ref = branch;
    await resolve(f.args);
    assert.deepEqual(f.outputs, { branch, sha: 'a'.repeat(40) });
  });
}

const invalid = {
  'missing PR': f => { f.args.prNumber = ''; },
  'unmerged PR': f => { f.pr.merged = false; },
  'open PR': f => { f.pr.state = 'open'; },
  'wrong repository': f => { f.pr.base.repo.full_name = 'other/repo'; },
  'main branch': f => { f.pr.base.ref = 'main'; },
  'topic branch': f => { f.pr.base.ref = 'release-0.3.1'; },
  'missing merge SHA': f => { f.pr.merge_commit_sha = null; },
  'advanced release branch': f => { f.ref.object.sha = 'b'.repeat(40); },
  'API failure': f => { f.args.github.rest.pulls.get = async () => { throw new Error('network'); }; },
};
for (const [name, mutate] of Object.entries(invalid)) {
  test(`rejects ${name} without release outputs`, async () => {
    const f = fixture(); mutate(f);
    await assert.rejects(resolve(f.args));
    assert.deepEqual(f.outputs, {});
  });
}
