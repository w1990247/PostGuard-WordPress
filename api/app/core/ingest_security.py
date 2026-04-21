import hmac
import hashlib
from datetime import datetime,timezone
from api.app.core.settings import settings, parsed_api_keys

#This function rejects stale requests so  old signed events dont get replayed.
def VerifyTimestamps(timestamp: int) ->None:

    now=int(datetime.now(timezone.utc).timestamp())
    
    if abs(now - timestamp)>settings.REPLAY_WINDOW_SECONDS:
        raise ValueError("The timestamp is outside the window!")
    

# The following function is  used to  verify the HMAC signature.
def VerifySignatures(api_key: str, timestamp: int, body: bytes, signature:str)-> None:

    keys= parsed_api_keys()

    if api_key not in keys:
        raise ValueError("API key is not known!")
    
    secretKey= keys[api_key].encode("utf-8")
    message1= f"{timestamp}.".encode("utf-8") +body
    expected = hmac.new(secretKey,message1, hashlib.sha256).hexdigest()

    if not hmac.compare_digest( expected, signature):
        raise ValueError("Bad signature!")