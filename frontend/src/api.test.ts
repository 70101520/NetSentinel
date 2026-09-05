// @vitest-environment jsdom
import {afterEach,describe,expect,it,vi} from 'vitest';
import {api,AuthenticationRequired,clearSession,hasSession,login} from './api';

function token(exp:number){return `x.${btoa(JSON.stringify({exp}))}.x`}
afterEach(()=>{clearSession();vi.restoreAllMocks()})

describe('authenticated API client',()=>{
  it('attaches a current token to Devices and Dashboard requests',async()=>{
    localStorage.setItem('netsentinel_access_token',token(Date.now()/1000+60));
    const fetchMock=vi.spyOn(globalThis,'fetch').mockImplementation(async()=>new Response('{}',{status:200}));
    await api('/api/v1/devices');await api('/api/v1/dashboard');
    expect(fetchMock).toHaveBeenCalledTimes(2);
    for(const call of fetchMock.mock.calls)expect((call[1]?.headers as Record<string,string>).Authorization).toMatch(/^Bearer /);
  });
  it('rejects unauthenticated and expired sessions without a request',async()=>{
    const fetchMock=vi.spyOn(globalThis,'fetch');await expect(api('/api/v1/devices')).rejects.toBeInstanceOf(AuthenticationRequired);
    localStorage.setItem('netsentinel_access_token',token(Date.now()/1000-60));expect(hasSession()).toBe(false);expect(fetchMock).not.toHaveBeenCalled();
  });
  it('clears invalid state on 401 and logout',async()=>{
    localStorage.setItem('netsentinel_access_token',token(Date.now()/1000+60));vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response('',{status:401}));
    await expect(api('/api/v1/devices')).rejects.toBeInstanceOf(AuthenticationRequired);expect(localStorage.getItem('netsentinel_access_token')).toBeNull();
    localStorage.setItem('netsentinel_access_token',token(Date.now()/1000+60));clearSession();expect(hasSession()).toBe(false);
  });
  it('stores login token and does not invent device data',async()=>{
    vi.spyOn(globalThis,'fetch').mockResolvedValue(new Response(JSON.stringify({access_token:token(Date.now()/1000+60)}),{status:200,headers:{'Content-Type':'application/json'}}));
    await login('admin@example.invalid','hidden');expect(hasSession()).toBe(true);expect(localStorage.length).toBe(1);
  });
});
