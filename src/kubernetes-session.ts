import { createPublicKey, verify, type JsonWebKey } from 'node:crypto';
import { isClientSessionLive } from './session-liveness';

export interface KubernetesSessionDependencies {
  issuer: string;
  clientId: string;
  jwks: { keys: Array<Record<string, unknown>> };
  redis: Parameters<typeof isClientSessionLive>[0];
  now?: () => number;
}

export interface KubernetesTokenReview {
  apiVersion: 'authentication.k8s.io/v1';
  kind: 'TokenReview';
  status: {
    authenticated: boolean;
    audiences?: string[];
    user?: { username: string; groups: string[] };
  };
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function strings(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function decode(part: string): unknown {
  if (!/^[A-Za-z0-9_-]+$/.test(part)) throw new Error('Invalid JWT encoding');
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

/** Caller must authenticate the API-server webhook before passing the request here. */
export async function reviewKubernetesToken(
  body: unknown,
  deps: KubernetesSessionDependencies
): Promise<KubernetesTokenReview> {
  const denied: KubernetesTokenReview = {
    apiVersion: 'authentication.k8s.io/v1',
    kind: 'TokenReview',
    status: { authenticated: false },
  };
  try {
    if (!record(body) || body.apiVersion !== denied.apiVersion || body.kind !== denied.kind
      || !record(body.spec) || typeof body.spec.token !== 'string'
      || body.spec.token.length > 32_768 || !deps.issuer || !deps.clientId) return denied;
    const requested = body.spec.audiences;
    if (requested !== undefined && (!strings(requested) || !requested.includes(deps.clientId))) return denied;
    const parts = body.spec.token.split('.');
    if (parts.length !== 3) return denied;
    const header = decode(parts[0]);
    const claims = decode(parts[1]);
    if (!record(header) || !record(claims) || header.alg !== 'RS256'
      || typeof header.kid !== 'string' || !header.kid || header.crit !== undefined
      || header.b64 !== undefined || !/^[A-Za-z0-9_-]+$/.test(parts[2])) return denied;
    const keys = deps.jwks.keys.filter((key) => key.kid === header.kid && key.kty === 'RSA'
      && (key.alg === undefined || key.alg === 'RS256') && (key.use === undefined || key.use === 'sig')
      && (key.key_ops === undefined || (strings(key.key_ops) && key.key_ops.includes('verify'))));
    if (keys.length !== 1) return denied;
    const key = createPublicKey({ key: keys[0] as JsonWebKey, format: 'jwk' });
    if (!verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2], 'base64url'))) return denied;
    const now = deps.now?.() ?? Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(now) || claims.iss !== deps.issuer || claims.aud !== deps.clientId
      || (claims.azp !== undefined && claims.azp !== deps.clientId)
      || typeof claims.exp !== 'number' || !Number.isSafeInteger(claims.exp) || claims.exp <= now
      || typeof claims.iat !== 'number' || !Number.isSafeInteger(claims.iat) || claims.iat > now
      || claims.iat <= 0 || claims.exp <= claims.iat
      || (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || !Number.isSafeInteger(claims.nbf) || claims.nbf > now))
      || typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 256 || /[\x00-\x1f\x7f]/.test(claims.sub)
      || typeof claims.sid !== 'string' || !/^[A-Za-z0-9_-]{8,128}$/.test(claims.sid)
      || !strings(claims.amr) || !claims.amr.includes('ad')
      || claims.amr.some((method) => /local|recovery|break.?glass/i.test(method))
      || !strings(claims.k3s_groups)) return denied;
    const groups = [...new Set(claims.k3s_groups)];
    if (!groups.includes('k3s:access') || !groups.some((group) => ['k3s:viewer', 'k3s:administrator'].includes(group))
      || groups.some((group) => !['k3s:access', 'k3s:viewer', 'k3s:administrator'].includes(group))) return denied;
    if (!await isClientSessionLive(deps.redis, claims.sid, deps.clientId, claims.sub)) return denied;
    return {
      ...denied,
      status: {
        authenticated: true,
        audiences: [deps.clientId],
        user: { username: `oidc:auth:${claims.sub}`, groups: groups.map((group) => `oidc:auth:${group}`) },
      },
    };
  } catch {
    // Includes malformed keys, cryptography errors, revoked sessions and Redis outages.
    return denied;
  }
}
