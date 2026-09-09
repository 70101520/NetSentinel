from cryptography.fernet import Fernet, InvalidToken
from app.config import settings

def _cipher()->Fernet:
    if not settings.snmp_credential_key:
        raise RuntimeError("SNMP credential encryption is not configured")
    try:return Fernet(settings.snmp_credential_key.encode("ascii"))
    except (ValueError,UnicodeEncodeError) as exc:raise RuntimeError("SNMP credential encryption key is invalid") from exc

def encrypt_snmp_secret(value:str)->str:return _cipher().encrypt(value.encode("utf-8")).decode("ascii")
def decrypt_snmp_secret(value:str)->str:
    try:return _cipher().decrypt(value.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:raise RuntimeError("SNMP credential cannot be decrypted") from exc
