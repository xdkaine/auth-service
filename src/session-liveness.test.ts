import { describe, expect, it } from 'vitest';
import { isClientSessionLive, SESSION_REVOCATION_PREFIX } from './session-liveness';
function fixture() {
 const values = new Map<string,string>();
 const redis = { get: async(k:string)=>values.get(k)??null, del:async(...ks:string[])=>ks.forEach(k=>values.delete(k)),
   async *scanIterator(){yield [...values.keys()].filter(k=>k.startsWith('oidc:Session:'));} };
 const p={kind:'Session',jti:'primary',accountId:'alice',exp:Date.now()/1000+600,authorizations:{client:{sid:'client-sid-123'}}};
 values.set('oidc:Session:primary',JSON.stringify(p));return {values,redis,p};
}
describe('online session revocation',()=>{
 it('accepts live exact identity then rejects retained sid after deletion',async()=>{
  const {values,redis}=fixture();expect(await isClientSessionLive(redis,'client-sid-123','client','alice')).toBe(true);
  values.delete('oidc:Session:primary');expect(await isClientSessionLive(redis,'client-sid-123','client','alice')).toBe(false);
 });
 it('tombstone rejects a stale snapshot',async()=>{const {values,redis}=fixture();values.set(SESSION_REVOCATION_PREFIX+'primary','1');expect(await isClientSessionLive(redis,'client-sid-123','client','alice')).toBe(false);});
 it.each([['other','alice'],['client','bob']])('rejects foreign client or subject %s %s',async(client,sub)=>{const {redis}=fixture();expect(await isClientSessionLive(redis,'client-sid-123',client,sub)).toBe(false);});
 it('rejects expired or malformed sessions',async()=>{const {values,redis,p}=fixture();p.exp=1;values.set('oidc:Session:primary',JSON.stringify(p));expect(await isClientSessionLive(redis,'client-sid-123','client','alice')).toBe(false);});
 it('fails closed on store error',async()=>{const {redis}=fixture();redis.get=async()=>{throw Error('down');};expect(await isClientSessionLive(redis,'client-sid-123','client','alice')).toBe(false);});
});
