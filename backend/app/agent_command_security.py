import base64
import hashlib
import hmac
import json
import secrets

CONTEXT=b"NetSentinel.Agent.Command.v1\0"

def password_verifier(value:str)->str:
    salt=secrets.token_bytes(16);iterations=600_000
    digest=hashlib.pbkdf2_hmac("sha256",value.encode(),salt,iterations,dklen=32)
    return f"pbkdf2-sha256${iterations}${_encode(salt)}${_encode(digest)}"

def signed_envelope(payload:dict,credential_secret:str)->dict:
    raw=json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
    signature=hmac.new(credential_secret.encode(),CONTEXT+raw,hashlib.sha256).digest()
    return {"payload":_encode(raw),"signature":_encode(signature),"algorithm":"HMAC-SHA256","key_context":"agent-credential-v1"}

def _encode(value:bytes)->str:return base64.urlsafe_b64encode(value).rstrip(b"=").decode()
