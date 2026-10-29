import test from 'node:test';
import assert from 'node:assert/strict';
import {fetchToken, AuthorizationServerMismatchError} from '@modelcontextprotocol/client';

const issuer = 'https://legitimate.example';
function provider() {
  return {
    clientMetadata: {},
    clientInformation: () => ({client_id: 'synthetic-client', client_secret: 'synthetic-secret', issuer}),
    prepareTokenRequest: () => new URLSearchParams({grant_type: 'client_credentials'}),
  };
}
function metadata(url) {
  return {issuer: url, token_endpoint: url + '/token', token_endpoint_auth_methods_supported: ['client_secret_basic']};
}

test('GHSA-6qxp-vccf-f47h: swapped authorization server receives no credential request', async () => {
  let requests = 0;
  await assert.rejects(fetchToken(provider(), 'https://attacker.example', {
    metadata: metadata('https://attacker.example'),
    fetchFn: async () => {requests++; throw Error('Unexpected credential request');},
  }), AuthorizationServerMismatchError);
  assert.equal(requests, 0);
});

test('OAuth positive control: matching issuer can exchange synthetic credentials', async () => {
  let requests = 0;
  const tokens = await fetchToken(provider(), issuer, {
    metadata: metadata(issuer),
    fetchFn: async (url, init) => {
      requests++;
      assert.equal(String(url), issuer + '/token');
      assert.equal(init.method, 'POST');
      assert.match(new Headers(init.headers).get('Authorization'), /^Basic /);
      return new Response(JSON.stringify({access_token: 'synthetic-token', token_type: 'Bearer'}), {
        status: 200, headers: {'Content-Type': 'application/json'},
      });
    },
  });
  assert.equal(requests, 1);
  assert.equal(tokens.access_token, 'synthetic-token');
});
