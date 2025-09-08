#!/usr/bin/env python3

import os, sys, json, base64, argparse, math, re, secrets, hmac, hashlib
from collections import Counter, defaultdict
import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- CONFIG: replace these with your resources ----------
AWS_PROFILE = "mkse-demo"
AWS_REGION = "ap-southeast-1"
KMS_KEY_ID = "" #replace with your kms key id
S3_BUCKET = "" #replace with your bucket name
DDB_TABLE = "mkse-demo-index"
PRP_SECRET_ARN = "" #replace with prp key
# --------------------------------------------------------------

session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
s3 = session.client('s3')
kms = session.client('kms')
dynamodb = session.client('dynamodb')
secretsmgr = session.client('secretsmanager')

STOPWORDS = set(["the","and","is","in","on","of","a","an","to","for","be","are","with","as","that","this","it","by","or","from","which"])

def simple_tokenize(text):
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    tokens = text.split()
    return [t for t in tokens if t not in STOPWORDS]

def sentences_list(text):
    sents = re.split(r'[.!?]+', text)
    return [s.strip() for s in sents if s.strip()]

def compute_improved_tfidf(docs, alpha_span=0.8, beta_pos=0.6, top_k=5):
    N = len(docs)
    doc_counts = {}
    doc_sent_positions = {}
    doc_first_pos = {}
    doc_total_tokens = {}
    df_counter = Counter()
    for doc_id, text in docs.items():
        tokens = simple_tokenize(text)
        doc_total_tokens[doc_id] = max(1, len(tokens))
        counts = Counter(tokens)
        doc_counts[doc_id] = counts
        for term in counts:
            df_counter[term] += 1
        sents = sentences_list(text)
        sent_pos = defaultdict(set)
        for i, sent in enumerate(sents):
            tks = simple_tokenize(sent)
            for t in set(tks):
                sent_pos[t].add(i)
        doc_sent_positions[doc_id] = sent_pos
        first_pos = {}
        for idx, t in enumerate(tokens):
            if t not in first_pos:
                first_pos[t] = idx
        doc_first_pos[doc_id] = first_pos

    tfidf_scores = {}
    keywords_per_doc = {}
    for doc_id, text in docs.items():
        tfidf_scores[doc_id] = {}
        counts = doc_counts[doc_id]
        total_tokens = doc_total_tokens[doc_id]
        sents = sentences_list(text)
        L = max(1, len(sents))
        for term, tf in counts.items():
            df = df_counter[term]
            idf = math.log((N)/(1+df)) if df > 0 else 0.0
            tfidf = (tf/total_tokens) * idf
            span = len(doc_sent_positions[doc_id].get(term, []))
            span_weight = 1.0 + alpha_span * (span / L)
            first = doc_first_pos[doc_id].get(term, 0)
            pos_norm = first / total_tokens if total_tokens > 0 else 0.0
            pos_weight = 1.0 + beta_pos * (1.0 - pos_norm)
            z = tfidf * span_weight * pos_weight
            tfidf_scores[doc_id][term] = z
        sorted_terms = sorted(tfidf_scores[doc_id].items(), key=lambda x: x[1], reverse=True)
        top_terms = [t for t, s in sorted_terms[:top_k]]
        keywords_per_doc[doc_id] = top_terms
    return tfidf_scores, keywords_per_doc

def add_virtual_keywords(keywords_per_doc, n_virtual=2):
    aug = {}
    for doc_id, kws in keywords_per_doc.items():
        new = list(kws)
        for _ in range(n_virtual):
            new.append(f"vk_{secrets.token_hex(4)}")
        aug[doc_id] = new
    return aug

def prp_label_from_key(key_bytes, keyword, label_len=16):
    hm = hmac.new(key_bytes, keyword.encode('utf-8'), hashlib.sha256).hexdigest()
    return hm[:label_len]

def read_prp_from_secret(secret_arn):
    # secret stored as JSON {"prp_key": "<hex>"}
    r = secretsmgr.get_secret_value(SecretId=secret_arn)
    ss = r.get('SecretString')
    j = json.loads(ss)
    return bytes.fromhex(j['prp_key'])

def get_prp_key_from_secret(secret_name=PRP_SECRET_ARN):
    resp = secretsmgr.get_secret_value(SecretId=secret_name)
    secret = json.loads(resp["SecretString"])
    return bytes.fromhex(secret["prp_key"])

def upload_and_index(docs_dir, top_k=4, n_virtual=2):
    # read files
    docs = {}
    for fname in os.listdir(docs_dir):
        if fname.lower().endswith('.txt'):
            with open(os.path.join(docs_dir, fname), 'r', encoding='utf-8') as f:
                docs[fname] = f.read()
    if not docs:
        print("no .txt files found in", docs_dir)
        return

    tfidf_scores, keywords_per_doc = compute_improved_tfidf(docs, top_k=top_k)
    aug = add_virtual_keywords(keywords_per_doc, n_virtual=n_virtual)
    prp_key = get_prp_key_from_secret();

    # for each doc: generate data key, encrypt with AESGCM, upload to S3, update DynamoDB postings
    for doc_id, text in docs.items():
        # 1. generate data key
        resp = kms.generate_data_key(KeyId=KMS_KEY_ID, KeySpec='AES_256')
        plaintext_data_key = resp['Plaintext']      # bytes
        ciphertext_data_key = resp['CiphertextBlob'] # bytes (this will be stored)

        # 2. encrypt doc with AES-GCM
        aesgcm = AESGCM(plaintext_data_key)
        iv = os.urandom(12)
        ct = aesgcm.encrypt(iv, text.encode('utf-8'), None)

        # 3. upload to S3
        s3_key = f"docs/{doc_id}.enc"
        s3.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=ct,
                      Metadata={
                          'ciphertext_data_key': base64.b64encode(ciphertext_data_key).decode('utf-8'),
                          'iv': base64.b64encode(iv).decode('utf-8')
                      })
        # 4. update DynamoDB for each keyword label
        kws = aug[doc_id]
        for kw in kws:
            lbl = prp_label_from_key(prp_key, kw)
            # DynamoDB UpdateItem: append posting to list 'postings'
            posting = {
                'M': {
                    'doc_id': {'S': doc_id},
                    'z': {'N': str(tfidf_scores.get(doc_id, {}).get(kw, 0.0001))},
                    's3_key': {'S': s3_key}
                }
            }
            # use update_item with list_append
            dynamodb.update_item(
                TableName=DDB_TABLE,
                Key={'label': {'S': lbl}},
                UpdateExpression="SET postings = list_append(if_not_exists(postings, :empty_list), :p)",
                ExpressionAttributeValues={
                    ':p': {'L': [posting]},
                    ':empty_list': {'L': []}
                }
            )
        print("uploaded", doc_id, "-> s3://{}/{}".format(S3_BUCKET, s3_key))

    print("Upload + indexing complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--docs_dir", default="./docs", help="folder containing .txt files")
    parser.add_argument("--top_k", type=int, default=5)
    parser.add_argument("--n_virtual", type=int, default=2)
    args = parser.parse_args()
    upload_and_index(args.docs_dir, top_k=args.top_k, n_virtual=args.n_virtual)
