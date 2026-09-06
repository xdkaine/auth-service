import { generateKeyPairSync, sign } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { reviewKubernetesToken, type KubernetesSessionDependencies } from './kubernetes-session';
import { isClientSessionLive } from './session-liveness';

vi.mock('./session-liveness', () => ({ isClientSessionLive: vi.fn() }));
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'test' };
const now = 1_800_000_000;
const base = {
  iss: 'https://auth.example.org', aud: 'headlamp', sub: 'alice', sid: 'client-session-123',
  iat: now - 1, exp: now + 600, amr: ['pwd', 'ad'], k3s_groups: ['k3s:access', 'k3s:viewer'],
};
const deps: KubernetesSessionDependencies = {
  issuer: base.iss, clientId: base.aud, jwks: { keys: [jwk] },
  redis: {} as KubernetesSessionDependencies['redis'], now: () => now,
};
function token(patch: Record<string, unknown> = {}, headerPatch: Record<string, unknown> = {}) {
  const parts = [ { alg: 'RS256', kid: 'test', ...headerPatch }, { ...base, ...patch } ]
    .map((part) => Buffer.from(JSON.stringify(part)).toString('base64url'));
  const signed = parts.join('.');
  return `${signed}.${sign('RSA-SHA256', Buffer.from(signed), pair.privateKey).toString('base64url')}`;
}
function review(jwt = token(), spec: Record<string, unknown> = {}) {
  return reviewKubernetesToken({ apiVersion: 'authentication.k8s.io/v1', kind: 'TokenReview', spec: { token: jwt, ...spec } }, deps);
}
beforeEach(() => { vi.mocked(isClientSessionLive).mockReset().mockResolvedValue(true); });
describe('Kubernetes live-session token review', () => {
  it('returns only fixed identity/group prefixes and checks the exact live session', async () => {
    const result = await review();
    expect(result.status).toEqual({ authenticated: true, audiences: ['headlamp'], user: {
      username: 'oidc:auth:alice', groups: ['oidc:auth:k3s:access', 'oidc:auth:k3s:viewer'],
    } });
    expect(isClientSessionLive).toHaveBeenCalledWith(deps.redis, base.sid, 'headlamp', 'alice');
  });
  it('allows an access administrator and deduplicates groups', async () => {
    expect((await review(token({ k3s_groups: ['k3s:access', 'k3s:administrator', 'k3s:access'] }))).status.user?.groups)
      .toEqual(['oidc:auth:k3s:access', 'oidc:auth:k3s:administrator']);
  });
  it.each([
    { iss: 'https://dev.example.org' }, { aud: 'cloud' }, { aud: ['headlamp', 'cloud'] }, { azp: 'cloud' },
    { exp: now }, { exp: '1800000001' }, { iat: now + 1 }, { iat: undefined }, { nbf: now + 1 },
    { sub: '' }, { sub: 'system:admin\n' }, { sid: undefined }, { sid: '../other-session' },
    { amr: ['pwd'] }, { amr: ['ad', 'local'] }, { amr: ['ad', 'break_glass'] },
    { k3s_groups: ['k3s:administrator'] }, { k3s_groups: ['k3s:access'] },
    { k3s_groups: ['k3s:access', 'cloud:administrator'] }, { k3s_groups: ['k3s:access', 'k3s:viewer', 'system:masters'] },
  ])('rejects invalid claims %j without checking session state', async (patch) => {
    expect((await review(token(patch))).status.authenticated).toBe(false);
    expect(isClientSessionLive).not.toHaveBeenCalled();
  });
  it.each([{ alg: 'HS256' }, { alg: 'none' }, { kid: 'unknown' }, { crit: ['custom'] }, { b64: false }])
    ('rejects unsupported headers %j', async (patch) => {
      expect((await review(token({}, patch))).status.authenticated).toBe(false);
    });
  it('rejects tampering', async () => {
    const jwt = token();
    const parts = jwt.split('.');
    parts[1] = Buffer.from(JSON.stringify({ ...base, sub: 'admin' })).toString('base64url');
    expect((await review(parts.join('.'))).status.authenticated).toBe(false);
  });
  it.each(['', 'not-a-token', 'a.b.c', 'x'.repeat(32_769)])('rejects malformed bounded tokens', async (jwt) => {
    expect((await review(jwt)).status.authenticated).toBe(false);
  });
  it('never caches positive session checks', async () => {
    const jwt = token();
    expect((await review(jwt)).status.authenticated).toBe(true);
    vi.mocked(isClientSessionLive).mockResolvedValue(false);
    expect((await review(jwt)).status).toEqual({ authenticated: false });
    expect(isClientSessionLive).toHaveBeenCalledTimes(2);
  });
  it('fails closed on session storage failure', async () => {
    vi.mocked(isClientSessionLive).mockRejectedValue(new Error('redis unavailable'));
    expect((await review()).status).toEqual({ authenticated: false });
  });
  it('honors requested audiences without reflecting unrelated audiences', async () => {
    expect((await review(token(), { audiences: ['other', 'headlamp'] })).status.audiences).toEqual(['headlamp']);
    expect((await review(token(), { audiences: ['other'] })).status.authenticated).toBe(false);
    expect((await review(token(), { audiences: 'headlamp' })).status.authenticated).toBe(false);
  });
  it('rejects unsupported review versions and malformed bodies', async () => {
    for (const body of [null, {}, { apiVersion: 'authentication.k8s.io/v1beta1', kind: 'TokenReview', spec: { token: token() } }]) {
      expect((await reviewKubernetesToken(body, deps)).status.authenticated).toBe(false);
    }
  });
});
