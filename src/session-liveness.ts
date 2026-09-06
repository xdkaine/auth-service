import type { ScanCapableRedis } from './backchannel';

export const SESSION_REVOCATION_PREFIX = 'authsvc:revoked-session:';

/** A signed token is insufficient: require its exact live client authorization. */
export async function isClientSessionLive(
  redis: ScanCapableRedis, sid: string, clientId: string, sub: string,
): Promise<boolean> {
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(sid) || !sub || sub.length > 512 || !clientId || !redis.scanIterator) return false;
  try {
    for await (const chunk of redis.scanIterator({ MATCH: 'oidc:Session:*', COUNT: 100 })) {
      for (const key of Array.isArray(chunk) ? chunk : [chunk]) {
        if (key.includes(':uid:') || key.includes(':userCode:')) continue;
        const raw = await redis.get(key);
        if (!raw) continue;
        let p;
        try { p = JSON.parse(raw); } catch { continue; }
        if (!p || p.kind !== 'Session' || typeof p.jti !== 'string' || key !== `oidc:Session:${p.jti}`
          || p.accountId !== sub || typeof p.exp !== 'number' || p.exp <= Date.now() / 1000
          || p.authorizations?.[clientId]?.sid !== sid) continue;
        // Check last: an in-flight reader cannot accept a deleted session snapshot.
        if (await redis.get(SESSION_REVOCATION_PREFIX + p.jti)) return false;
        return (await redis.get(key)) !== null;
      }
    }
    return false;
  } catch { return false; }
}
