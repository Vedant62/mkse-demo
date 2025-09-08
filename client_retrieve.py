#!/usr/bin/env python3
import boto3, base64, json, os, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AWS_PROFILE = "mkse-demo"
AWS_REGION = "ap-southeast-1"
S3_BUCKET = "" #replace with your s3 bucket name
DDB_TABLE = "mkse-demo-index"
KMS_KEY_ID = "" #replace with your kms key id

session = boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)
s3 = session.client("s3")
dynamodb = session.client("dynamodb")
kms = session.client("kms")

def fetch_postings(label):
    resp = dynamodb.get_item(
        TableName=DDB_TABLE,
        Key={"label": {"S": label}}
    )
    if "Item" not in resp:
        print(f"No postings for label {label}")
        return []
    return resp["Item"]["postings"]["L"]

def download_and_decrypt(posting, outdir="results"):
    doc_id = posting["M"]["doc_id"]["S"]
    s3_key = posting["M"]["s3_key"]["S"]

    # Get object + metadata
    obj = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
    ct = obj["Body"].read()
    metadata = obj["Metadata"]

    ciphertext_data_key = base64.b64decode(metadata["ciphertext_data_key"])
    iv = base64.b64decode(metadata["iv"])

    # Decrypt the data key via KMS
    resp = kms.decrypt(CiphertextBlob=ciphertext_data_key, KeyId=KMS_KEY_ID)
    data_key = resp["Plaintext"]

    # AES-GCM decrypt
    aesgcm = AESGCM(data_key)
    plaintext = aesgcm.decrypt(iv, ct, None).decode("utf-8")

    # Save locally
    os.makedirs(outdir, exist_ok=True)
    outfile = os.path.join(outdir, f"{doc_id}.txt")
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(plaintext)
    print(f"[+] Saved {doc_id} -> {outfile}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True, help="Trapdoor label to fetch docs")
    parser.add_argument("--k", type=int, default=1, help="Top-k results to save")
    args = parser.parse_args()

    postings = fetch_postings(args.label)
    if not postings:
        return

    # Just take top-k
    for posting in postings[:args.k]:
        download_and_decrypt(posting)

if __name__ == "__main__":
    main()
