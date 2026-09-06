const TOKEN_KEY='netsentinel_access_token';

export class AuthenticationRequired extends Error{}
export class ApiFailure extends Error{constructor(public status:number){super('The server could not complete this request.');}}

export function storedToken(){return localStorage.getItem(TOKEN_KEY)}
export function clearSession(){localStorage.removeItem(TOKEN_KEY)}
export function tokenIsCurrent(token:string){
  try{const payload=JSON.parse(atob(token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));return typeof payload.exp==='number'&&payload.exp*1000>Date.now()}
  catch{return false}
}
export function hasSession(){const token=storedToken();if(!token||!tokenIsCurrent(token)){clearSession();return false}return true}

export async function login(email:string,password:string){
  const body=new URLSearchParams({username:email,password});
  const response=await fetch('/api/v1/auth/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
  if(!response.ok)throw new AuthenticationRequired('Email or password is incorrect.');
  const result=await response.json();localStorage.setItem(TOKEN_KEY,result.access_token);
}

export async function api<T>(path:string,init:RequestInit={}){
  const token=storedToken();if(!token||!tokenIsCurrent(token)){clearSession();throw new AuthenticationRequired('Your session has expired. Please sign in again.')}
  const response=await fetch(path,{...init,headers:{...init.headers,Authorization:`Bearer ${token}`}});
  if(response.status===401){clearSession();throw new AuthenticationRequired('Your session has expired. Please sign in again.')}
  if(!response.ok)throw new ApiFailure(response.status);
  return response.json() as Promise<T>;
}
