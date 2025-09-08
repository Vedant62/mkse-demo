# search_lambda.py
import json
import boto3
import os
from decimal import Decimal

dynamodb = boto3.client('dynamodb')
INDEX_TABLE = os.environ.get('INDEX_TABLE_NAME', 'mkse-demo-index')
S3_BUCKET = os.environ.get('S3_BUCKET', None)

def parse_postings_ddb(ddb_attr):
    # ddb_attr is DynamoDB JSON. Convert to python list of dicts.
    # Expect attribute 'postings' is a List of Maps with keys doc_id (S), z (N), s3_key (S)
    # This helper expects the raw response from get_item and will parse postings accordingly.
    res = []
    if not ddb_attr:
        return res
    for item in ddb_attr.get('L', []):
        m = item.get('M', {})
        doc_id = m.get('doc_id', {}).get('S')
        z = float(m.get('z', {}).get('N', '0'))
        s3_key = m.get('s3_key', {}).get('S')
        res.append({'doc_id': doc_id, 'z': z, 's3_key': s3_key})
    return res

def lambda_handler(event, context):
    # event.body: {"labels":["abcd1234",...], "k":3}
    try:
        body = event.get('body')
        if isinstance(body, str):
            body = json.loads(body)
        labels = body.get('labels', [])
        k = int(body.get('k', 3))
    except Exception:
        return {"statusCode":400, "body": json.dumps({"error":"invalid request"})}

    doc_scores = {}
    doc_s3 = {}
    for lbl in labels:
        resp = dynamodb.get_item(TableName=INDEX_TABLE, Key={'label': {'S': lbl}})
        if 'Item' not in resp:
            continue
        item = resp['Item']
        postings_attr = item.get('postings')
        postings = parse_postings_ddb(postings_attr)
        for p in postings:
            doc_id = p['doc_id']
            z = p['z']
            doc_scores[doc_id] = doc_scores.get(doc_id, 0.0) + z
            doc_s3[doc_id] = p.get('s3_key')

    ranked = sorted(doc_scores.items(), key=lambda x: x[1], reverse=True)[:k]
    results = []
    for doc_id, score in ranked:
        results.append({
            'doc_id': doc_id,
            'score': score,
            's3_key': doc_s3.get(doc_id)
        })
    return {"statusCode": 200, "body": json.dumps({"results": results})}
