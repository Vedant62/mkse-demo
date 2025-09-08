# trapdoor_lambda.py
import json
import boto3
import hmac
import hashlib
import os

secrets_client = boto3.client('secretsmanager')
SECRET_ARN = os.environ.get('PRP_SECRET_ARN', None)

def get_prp_key():
    resp = secrets_client.get_secret_value(SecretId=SECRET_ARN)
    secret = resp.get('SecretString')
    # assume it's a JSON string
    try:
        secret_json = json.loads(secret)
        prp_hex = secret_json.get('prp_key')
    except Exception:
        
        prp_hex = secret
    return bytes.fromhex(prp_hex)

def lambda_handler(event, context):
    #body contains {"keywords": ["network","host"]}
    try:
        body = event.get('body')
        if isinstance(body, str):
            body = json.loads(body)
        keywords = body.get('keywords', [])
    except Exception as e:
        return {"statusCode":400, "body": json.dumps({"error": "invalid body"})}

    prp_key = get_prp_key()
    labels = []
    for kw in keywords:
        hm = hmac.new(prp_key, kw.encode('utf-8'), hashlib.sha256).hexdigest()
        labels.append(hm[:16])
    return {
        "statusCode": 200,
        "body": json.dumps({"labels": labels})
    }
