import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthConfig } from './config';
import { evaluateApplicationAccess, validateAccessPolicy } from './application-access';

const mocks = vi.hoisted(() => ({ findUnique: vi.fn(), directory: vi.fn() }));
vi.mock('./db', () => ({ prisma: { oidcClient: { findUnique: mocks.findUnique } } }));
vi.mock('./ldap', () => ({ loadAdAdminState: mocks.directory }));

const config = {} as AuthConfig;
const groupDn = 'CN=K3s Readers,OU=Groups,DC=example,DC=test';
const policy = { restricted: true, mappings: [{ groupDn, role: 'viewer' }] };
const denied = { restricted: true, allowed: false, groups: [] };

beforeEach(() => {
  vi.resetAllMocks();
  mocks.findUnique.mockResolvedValue({ enabled: true, accessPolicy: policy });
  mocks.directory.mockResolvedValue({ ok: true, disabled: false, locked: false, memberOf: [groupDn] });
});

describe('validateAccessPolicy', () => {
  it('accepts deny-all and explicit unrestricted policies', () => {
    expect(validateAccessPolicy({ restricted: true, mappings: [] })).toEqual({ restricted: true, mappings: [] });
    expect(validateAccessPolicy({ restricted: false, mappings: [] })).toEqual({ restricted: false, mappings: [] });
  });
  it('accepts full DNs with escaped separators', () => {
    const escaped = { restricted: true, mappings: [{ groupDn: 'CN=K3s\\, Operators,OU=Groups,DC=example,DC=test', role: 'administrator' }] };
    expect(validateAccessPolicy(escaped)).toEqual(escaped);
  });
  it.each([
    null, undefined, [], {}, true, '{"restricted":false}',
    { restricted: 'false', mappings: [] },
    { restricted: false },
    { restricted: true, mappings: [], bypass: true },
    { restricted: true, mappings: [{ groupDn, role: 'cluster-admin' }] },
    { restricted: true, mappings: [{ groupDn, role: 'viewer', groups: ['system:masters'] }] },
    ...['K3s Readers', 'CN=K3s Readers', 'CN=Readers,,DC=test', 'CN=Readers,DC=', 'CN=Readers,DC=test\n', 'CN=Readers,DC=test\\', 'CN=Readers,INVALID=x,DC=test'].map((dn) => ({ restricted: true, mappings: [{ groupDn: dn, role: 'viewer' }] })),
    { restricted: true, mappings: Array.from({ length: 33 }, (_, i) => ({ groupDn: `CN=Group${i},DC=test`, role: 'viewer' })) },
  ])('rejects malformed policy %j', (value) => {
    expect(validateAccessPolicy(value)).toBeNull();
  });
  it('rejects duplicate case-insensitive mapping pairs', () => {
    expect(validateAccessPolicy({ restricted: true, mappings: [...policy.mappings, { groupDn: groupDn.toUpperCase(), role: 'viewer' }] })).toBeNull();
  });
});

describe('evaluateApplicationAccess', () => {
  it('matches only complete case-insensitive AD DNs and emits fixed mapped roles', async () => {
    mocks.directory.mockResolvedValue({ ok: true, disabled: false, locked: false, memberOf: [groupDn.toUpperCase(), groupDn] });
    expect(await evaluateApplicationAccess(config, 'headlamp', 'alice')).toEqual({ restricted: true, allowed: true, groups: ['k3s:viewer'] });
    expect(mocks.directory).toHaveBeenCalledWith(config, 'alice');
    expect(mocks.findUnique).toHaveBeenCalledWith({ where: { clientId: 'headlamp' } });
  });
  it('deduplicates roles across different matching groups', async () => {
    const other = 'CN=Other,OU=Groups,DC=example,DC=test';
    mocks.findUnique.mockResolvedValue({ enabled: true, accessPolicy: { restricted: true, mappings: [...policy.mappings, { groupDn: other, role: 'viewer' }, { groupDn: other, role: 'administrator' }] } });
    mocks.directory.mockResolvedValue({ ok: true, disabled: false, locked: false, memberOf: [groupDn, other] });
    expect(await evaluateApplicationAccess(config, 'headlamp', 'alice')).toEqual({ restricted: true, allowed: true, groups: ['k3s:administrator', 'k3s:viewer'] });
  });
  it.each([[], ['K3s Readers'], ['CN=K3s Readers,OU=Other,DC=example,DC=test'], ['CN=K3s Readers,OU=Groups,DC=other,DC=test']])('denies absent or misleading membership %j', async (...members) => {
    const memberOf = members.length === 1 && Array.isArray(members[0]) ? members[0] : members;
    mocks.directory.mockResolvedValue({ ok: true, disabled: false, locked: false, memberOf });
    expect(await evaluateApplicationAccess(config, 'headlamp', 'alice')).toEqual(denied);
  });
  it.each([
    { ok: false, reason: 'unavailable' }, { ok: false, reason: 'not_found' }, { ok: false, reason: 'unconfigured' },
    { ok: true, disabled: true, locked: false, memberOf: [groupDn] },
    { ok: true, disabled: false, locked: true, memberOf: [groupDn] },
    { ok: true, disabled: false, locked: false, memberOf: [null] },
  ])('denies directory failure and unusable accounts %j', async (state) => {
    mocks.directory.mockResolvedValue(state);
    expect(await evaluateApplicationAccess(config, 'headlamp', 'alice')).toEqual(denied);
  });
  it.each([null, { enabled: false, accessPolicy: policy }, { enabled: true }, { enabled: true, accessPolicy: null }])('denies unknown, disabled or malformed client %j', async (row) => {
    mocks.findUnique.mockResolvedValue(row);
    expect(await evaluateApplicationAccess(config, 'headlamp', 'alice')).toEqual(denied);
    expect(mocks.directory).not.toHaveBeenCalled();
  });
  it('denies empty restrictions without querying AD', async () => {
    mocks.findUnique.mockResolvedValue({ enabled: true, accessPolicy: { restricted: true, mappings: [] } });
    expect(await evaluateApplicationAccess(config, 'headlamp', 'alice')).toEqual(denied);
    expect(mocks.directory).not.toHaveBeenCalled();
  });
  it('emits no mapped groups for unrestricted clients', async () => {
    mocks.findUnique.mockResolvedValue({ enabled: true, accessPolicy: { ...policy, restricted: false } });
    expect(await evaluateApplicationAccess(config, 'portal', 'alice')).toEqual({ restricted: false, allowed: true, groups: [] });
    expect(mocks.directory).not.toHaveBeenCalled();
  });
  it('denies database and unexpected directory exceptions', async () => {
    mocks.findUnique.mockRejectedValueOnce(new Error('database unavailable'));
    expect(await evaluateApplicationAccess(config, 'headlamp', 'alice')).toEqual(denied);
    mocks.directory.mockRejectedValueOnce(new Error('directory unavailable'));
    expect(await evaluateApplicationAccess(config, 'headlamp', 'alice')).toEqual(denied);
  });
  it('rechecks policy and membership on every evaluation', async () => {
    expect((await evaluateApplicationAccess(config, 'headlamp', 'alice')).allowed).toBe(true);
    mocks.directory.mockResolvedValueOnce({ ok: true, disabled: false, locked: false, memberOf: [] });
    expect(await evaluateApplicationAccess(config, 'headlamp', 'alice')).toEqual(denied);
    mocks.findUnique.mockResolvedValueOnce({ enabled: true, accessPolicy: { restricted: true, mappings: [] } });
    expect(await evaluateApplicationAccess(config, 'headlamp', 'alice')).toEqual(denied);
    expect(mocks.findUnique).toHaveBeenCalledTimes(3);
    expect(mocks.directory).toHaveBeenCalledTimes(2);
  });
});

describe.each(['k3s', 'tbd', 'cloud'] as const)('%s mandatory access and role isolation', (application) => {
  const access = `CN=${application}-access,OU=Groups,DC=example,DC=org`;
  const admin = `CN=${application}-administrator,OU=Groups,DC=example,DC=org`;
  const normalRole = application === 'k3s' ? 'viewer' : 'user';
  beforeEach(() => {
    mocks.findUnique.mockResolvedValue({ enabled: true, accessPolicy: {
      restricted: true, application, requiredGroupDns: [access],
      mappings: [{ groupDn: access, role: normalRole }, { groupDn: admin, role: 'administrator' }],
    } });
  });
  it.each([
    { memberships: [], roles: [] },
    { memberships: [admin], roles: [] },
    { memberships: [access], roles: ['access', normalRole] },
    { memberships: [access, admin], roles: ['access', 'administrator', normalRole] },
  ])('enforces access prerequisite for $memberships', async ({ memberships, roles }) => {
    mocks.directory.mockResolvedValue({ ok: true, disabled: false, locked: false, memberOf: memberships });
    expect(await evaluateApplicationAccess(config, application, 'alice')).toEqual({
      restricted: true, allowed: roles.length > 0, groups: roles.map((role) => `${application}:${role}`).sort(),
    });
  });
  it('does not accept membership from another application', async () => {
    mocks.directory.mockResolvedValue({ ok: true, disabled: false, locked: false,
      memberOf: ['CN=unrelated-access,OU=Groups,DC=example,DC=org', admin] });
    expect(await evaluateApplicationAccess(config, application, 'alice')).toEqual(denied);
  });
});

describe('prerequisite policy validation', () => {
  it.each([
    { application: 'portal' }, { application: null }, { requiredGroupDns: null },
    { requiredGroupDns: ['Readers'] }, { requiredGroupDns: [groupDn, groupDn.toUpperCase()] },
    { requiredGroupDns: Array.from({ length: 33 }, (_, i) => `CN=Required${i},DC=org`) },
    { application: 'cloud', mappings: [{ groupDn, role: 'viewer' }] },
    { application: 'k3s', mappings: [{ groupDn, role: 'user' }] },
  ])('fails closed for malformed extension %j', (extension) => {
    expect(validateAccessPolicy({ ...policy, ...extension })).toBeNull();
  });
  it('requires every prerequisite even when a role matches', async () => {
    mocks.findUnique.mockResolvedValue({ enabled: true, accessPolicy: {
      ...policy, requiredGroupDns: [groupDn, 'CN=Additional,DC=example,DC=org'],
    } });
    expect(await evaluateApplicationAccess(config, 'headlamp', 'alice')).toEqual(denied);
  });
  it('does not emit access marker without a matching role', async () => {
    mocks.findUnique.mockResolvedValue({ enabled: true, accessPolicy: {
      restricted: true, requiredGroupDns: [groupDn],
      mappings: [{ groupDn: 'CN=Other,DC=example,DC=org', role: 'administrator' }],
    } });
    expect(await evaluateApplicationAccess(config, 'headlamp', 'alice')).toEqual(denied);
  });
});
