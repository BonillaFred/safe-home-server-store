import requests

_GET_KEY_URL = 'https://localhost:8080/publickey'
_ENCRYPT_URL = 'https://localhost:8080/encrypt'
_DECRYPT_URL = 'https://localhost:8080/decrypt'


def _requestCheck(req: requests.request):
    if req is None:
        raise NameError("Null request: Call admin")
    if req.status_code != 200:
        raise NameError("Request failed with code: " + str(req.status_code))
    return req.json()


def _makeRequest(url: str, data: dict = None):
    fetched = None
    try:
        if(data is None):
            fetched = requests.get(url, verify='./certs/serverCert.crt')
        else:
            fetched = requests.post(url, json=data, verify='./certs/serverCert.crt')
        fetched = _requestCheck(fetched)
    except Exception as e:
        print("Failed to get data:\n" + str(e))
        exit(-1)

    return fetched

def decryptMessage(ciphertext, url=_DECRYPT_URL):
    return _makeRequest(url, data={"message":ciphertext})

def encryptMessage(plaintext, encript_url=_ENCRYPT_URL, pub_key_url=_GET_KEY_URL):
    pubKey = _makeRequest(pub_key_url)
    pubKey["message"] = plaintext
    return _makeRequest(encript_url, data=pubKey)

def getPublicKey(pub_key_url=_GET_KEY_URL):
    return _makeRequest(pub_key_url)
