import type { AuthConfig } from './config';
import { prisma } from './db';
import { loadAdAdminState } from './ldap';

export type ApplicationAccessRole = 'viewer' | 'administrator';
export type ApplicationAccessPolicy = {
  restricted: boolean;
  mappings: Array<{ groupDn: string; role: ApplicationAccessRole }>;
};
export type ApplicationAccessResult = {
  restricted: boolean;
  allowed: boolean;
  groups: string[];
};

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

// Require a full AD group DN. Keep its complete spelling for comparison rather
// than reducing it to a CN, which is not unique across directory containers.
function fullGroupDn(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 2048 || value !== value.trim()
    || /[\u0000-\u001f\u007f]/u.test(value)) return false;
  const components = value.match(/(?:\\[\s\S]|[^,\\])+/gu);
  if (!components || components.join(',') !== value || components.length < 2) return false;
  const componentPattern = /^(?:CN|OU|DC)=(?:\\(?:[0-9a-f]{2}|[,=+<>#;"\\ ])|[^,=+<>#;"\\\s](?:[^,=+<>#;"\\]|\\(?:[0-9a-f]{2}|[,=+<>#;"\\ ]))*)$/iu;
  return /^CN=/iu.test(components[0])
    && components.every((part) => componentPattern.test(part))
    && /^DC=/iu.test(components[components.length - 1]);
}

/** Invalid persisted policy is never interpreted as unrestricted access. */
export function validateAccessPolicy(value: unknown): ApplicationAccessPolicy | null {
  if (!record(value) || !exactKeys(value, ['restricted', 'mappings'])
    || typeof value.restricted !== 'boolean' || !Array.isArray(value.mappings)
    || value.mappings.length > 32) return null;
  const mappings: ApplicationAccessPolicy['mappings'] = [];
  const seen = new Set<string>();
  for (const mapping of value.mappings) {
    if (!record(mapping) || !exactKeys(mapping, ['groupDn', 'role'])
      || !fullGroupDn(mapping.groupDn)
      || (mapping.role !== 'viewer' && mapping.role !== 'administrator')) return null;
    const key = `${mapping.groupDn.toLowerCase()}\0${mapping.role}`;
    if (seen.has(key)) return null;
    seen.add(key);
    mappings.push({ groupDn: mapping.groupDn, role: mapping.role });
  }
  return { restricted: value.restricted, mappings };
}

/** Bootstrap clients are exempted explicitly by the caller, never by DB failure. */
export async function evaluateApplicationAccess(
  config: AuthConfig,
  clientId: string,
  username: string,
): Promise<ApplicationAccessResult> {
  const denied: ApplicationAccessResult = { restricted: true, allowed: false, groups: [] };
  try {
    const row = await prisma.oidcClient.findUnique({ where: { clientId } });
    if (!row || row.enabled !== true) return denied;
    const policy = validateAccessPolicy((row as typeof row & { accessPolicy?: unknown }).accessPolicy);
    if (!policy) return denied;
    if (!policy.restricted) return { restricted: false, allowed: true, groups: [] };
    if (!username.trim() || policy.mappings.length === 0) return denied;
    const directory = await loadAdAdminState(config, username);
    if (!directory.ok || directory.disabled || directory.locked
      || !Array.isArray(directory.memberOf)
      || directory.memberOf.some((group) => typeof group !== 'string')) return denied;
    const memberOf = new Set(directory.memberOf.map((group) => group.toLowerCase()));
    const groups = [...new Set(policy.mappings
      .filter((mapping) => memberOf.has(mapping.groupDn.toLowerCase()))
      .map((mapping) => `k3s:${mapping.role}`))].sort();
    return { restricted: true, allowed: groups.length > 0, groups };
  } catch {
    return denied;
  }
}
