import { describe, expect, it, vi } from 'vitest';
import Provider from 'oidc-provider';
import { buildProviderOptions } from './provider-options';
import type { AuthConfig } from './config';

const config = { issuer: 'https://auth.example.test', clientId: 'bootstrap', clientSecret: 'secret', redirectUris: ['https://app.example.test/callback'], postLogoutRedirects: [], cookieKeys: ['key'], ldapDomain: 'example.test' } as AuthConfig;
function fixture() {
  const check = vi.fn().mockResolvedValue({ allowed: true, restricted: true, groups: ['k3s:viewer'] });
  const options = buildProviderOptions(config, { redis: { get: async () => null }, createAdapter: () => { throw Error('unused'); }, checkApplicationAccess: check });
  const find = options.findAccount as (ctx: unknown, id: string, token?: unknown) => Promise<{ claims: () => Promise<Record<string, unknown>> }>;
  return { check, options, find };
}
describe('restricted provider account and token gates', () => {
  it('denies an existing SSO account before authorization completes', async () => {
    const { find, check } = fixture();
    check.mockResolvedValue({ allowed: false, restricted: true, groups: [] });
    await expect(find({ oidc: { client: { clientId: 'headlamp' } } }, 'alice')).rejects.toThrow('access_denied');
  });
  it('rechecks live policy when issuing claims after account loading', async () => {
    const { find, check } = fixture();
    const account = await find({ oidc: { client: { clientId: 'headlamp' } } }, 'alice');
    check.mockResolvedValue({ allowed: false, restricted: true, groups: [] });
    await expect(account.claims()).rejects.toThrow('access_denied');
  });
  it('uses the token client when no authorization context is present', async () => {
    const { find, check } = fixture();
    await (await find({}, 'alice', { clientId: 'headlamp' })).claims();
    expect(check).toHaveBeenLastCalledWith('headlamp', 'alice');
  });
  it('does not emit mapped roles for unrestricted clients', async () => {
    const { find, check } = fixture();
    check.mockResolvedValue({ allowed: true, restricted: false, groups: [] });
    expect(await (await find({ oidc: { client: { clientId: 'other' } } }, 'alice')).claims()).not.toHaveProperty('k3s_groups');
  });
  it('keeps non-Kubernetes application roles out of Kubernetes claims', async () => {
    const { find, check } = fixture();
    check.mockResolvedValue({ allowed: true, restricted: true, groups: ['tbd:access', 'tbd:administrator'] });
    const claims = await (await find({ oidc: { client: { clientId: 'tbd' } } }, 'alice')).claims();
    expect(claims.application_roles).toEqual(['tbd:access', 'tbd:administrator']);
    expect(claims).not.toHaveProperty('k3s_groups');
  });
  it('denies a missing client identity', async () => {
    await expect(fixture().find({}, 'alice')).rejects.toThrow('access_denied');
  });
  it('retains mapped groups under the actual conforming ID-token openid mask', async () => {
    const { options, find } = fixture();
    const account = await find({ oidc: { client: { clientId: 'bootstrap' } } }, 'alice');
    const provider = new Provider(config.issuer, options) as unknown as {
      Client: { find(id: string): Promise<unknown> };
      IdToken: new (claims: Record<string, unknown>, options: { ctx: object }) => {
        scope: string; mask: Record<string, unknown>; payload(): Promise<Record<string, unknown>>;
      };
    };
    const client = await provider.Client.find('bootstrap');
    const token = new provider.IdToken(await account.claims(), { ctx: { oidc: { client } } });
    token.scope = 'openid'; token.mask = {};
    expect(await token.payload()).toMatchObject({ k3s_groups: ['k3s:viewer'] });
  });
});
