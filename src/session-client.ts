import type { AuthConfig } from './config';
import { prisma } from './db';
import { decryptClientSecret } from './secret-encryption';
import { verifyClientCredentials } from './backchannel';

export async function authenticateSessionClient(header: string | string[] | undefined, config: AuthConfig): Promise<string | null> {
  const h = Array.isArray(header) ? header[0] : header;
  if (!h || h.length > 4096 || !h.startsWith('Basic ')) return null;
  const raw = Buffer.from(h.slice(6), 'base64').toString('utf8');
  const id = raw.slice(0, raw.indexOf(':'));
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(id)) return null;
  if (id === config.clientId) return verifyClientCredentials(header, id, config.clientSecret) ? id : null;
  const row = await prisma.oidcClient.findUnique({ where: { clientId: id } });
  if (!row || !row.enabled) return null;
  const secret = decryptClientSecret(row.secret);
  return secret && verifyClientCredentials(header, id, secret) ? id : null;
}
