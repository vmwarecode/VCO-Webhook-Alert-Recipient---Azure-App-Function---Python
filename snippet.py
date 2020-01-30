import logging
import hashlib
import hmac

import azure.functions as func

SECRET = '9ea6a0b0f9161f6176df540b1a57de09'

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    method = req.method
    if method == 'GET':
        return func.HttpResponse(
             "OK",
             status_code=200
        )        

    elif method == 'POST':
        post_data = req.get_body()
        signature_header = req.headers.get('x-webhook-signature')
        if signature_header:
            signature = parse_signature(signature_header)
            hmac = signature['s']
            message = '%s.%s' % (post_data.decode('utf-8'), signature['t'])
            computed_hmac = hmac_sha256(message, SECRET)
            if hmac != computed_hmac:
                return func.HttpResponse(
                    "Request signature invalid!",
                    status_code=400
                )
        return func.HttpResponse(
             "OK",
             status_code=200
        )
    
    return func.HttpResponse(
            "HTTP method not supported",
            status_code=405
    )


    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello {name}!")
    else:
        return func.HttpResponse(
             "Please pass a name on the query string or in the request body",
             status_code=400
        )

def parse_signature(value):
    parts = value.split('&')
    ret = {}
    for kv in parts:
        (k, v) = kv.split('=')
        ret[k] = v
    return ret

def hmac_sha256(message, secret):
    message = bytes(message, 'utf-8')
    secret = bytes(secret, 'utf-8')
    hash = hmac.new(secret, message, hashlib.sha256)
    return hash.hexdigest()
