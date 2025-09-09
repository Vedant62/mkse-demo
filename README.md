# MKSE PoC - Multi-Keyword Searchable Encryption on AWS

A proof-of-concept implementation of searchable encryption that enables secure keyword searches over encrypted documents stored in the cloud without revealing document contents or search queries to the cloud provider.

## Problem Statement

Organizations today generate massive amounts of sensitive data (medical records, legal documents, financial reports). While private cloud storage is secure, it comes with significant costs and limitations:

- **Infrastructure cost**: Maintaining private servers, storage, and redundancy is expensive
- **Scalability limits**: On-demand scaling requires significant upfront investment  
- **Operational overhead**: Managing upgrades, security patches, and compliance in-house is resource-intensive

Public cloud is cheaper and highly scalable, but the cloud provider is often "honest-but-curious" - they may follow protocols while analyzing your stored data or queries to learn sensitive information. Directly uploading plaintext documents or queries leaks private content.

This project tackles the problem of **how to search over encrypted data on an untrusted cloud server** without revealing either the contents of documents or the plaintext search queries.

## System Overview

The system uses a three-party model with cryptographic techniques to ensure privacy:

### Architecture

<img width="938" height="464" alt="image" src="https://github.com/user-attachments/assets/2b9d450b-4b59-4c5e-a4b5-5dfd6d76b08e" />


### Core Components

1. **Data Owner**
   - Uploads documents and extracts top-k TF-IDF keywords per document
   - Converts keywords → obfuscated labels using a PRP (Pseudo-Random Permutation) key
   - Encrypts documents with AES-GCM using per-document data keys from AWS KMS
   - Stores encrypted index (labels → postings) in DynamoDB

2. **Cloud Server (Untrusted Cloud, here AWS)**
   > not to be confused with the search service which is also using AWS 
   - Stores encrypted documents in S3 and encrypted index in DynamoDB
   - Executes search queries over obfuscated labels (trapdoors)
   - Never sees plaintext documents or plaintext queries

4. **Client (Authorized User)**
   - Submits plaintext keywords to `/trapdoor` Lambda for label conversion
   - Sends trapdoor labels to `/search` Lambda for DynamoDB queries
   - Fetches encrypted documents from S3 and decrypts locally using KMS

## Key Features

- **Privacy-Preserving**: Documents and queries remain encrypted/obfuscated in the cloud
- **TF-IDF Ranking**: Intelligent keyword extraction with span and position weighting
- **Virtual Keywords**: Noise injection to prevent frequency analysis attacks
- **AWS KMS Integration**: Secure key management with per-document data keys
- **Serverless Architecture**: Cost-effective Lambda-based implementation

## Project Structure

```
mkse-poc/
├── README.md
├── requirements.txt
├── .gitignore
├── owner_uploader.py          # Document upload and indexing
├── trapdoor_lambda.py         # Keyword → label conversion
├── search_lambda.py           # Search over encrypted index
├── client_retrieve.py         # Document retrieval and decryption
├── mkse-lambda-policy.json    # IAM policy template
├── trust-policy.json          # Lambda trust policy
└── docs/                      # Sample docs for testing
```

## Quick Concepts

- **Owner** extracts top-k TF-IDF keywords for each document with span & position weighting
- **Keywords** → PRP labels using HMAC-SHA256 keyed with PRP secret before cloud storage
- **Index** (label → postings) stored in DynamoDB with document scores and S3 keys
- **Documents** encrypted client-side using per-document AES-GCM data keys from AWS KMS
- **Encrypted data keys** and initialization vectors stored as S3 object metadata
- **Clients** convert keywords → trapdoor labels, search encrypted index, and decrypt results locally

## Prerequisites

- macOS or Linux with Python 3.8+
- AWS account with IAM permissions for resource creation
- AWS CLI v2 installed and configured

### Install Dependencies

```bash
# Install AWS CLI v2 (macOS)
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /

# Verify installation
aws --version

# Install Python dependencies
python3 -m pip install -r requirements.txt
```

## Quick Start

**Note**: Replace placeholders (`<ACCOUNT_ID>`, `<UNIQUE_SUFFIX>`, etc.) with your actual values. This guide assumes AWS region `ap-southeast-1`.

### 1. Configure AWS CLI

```bash
aws configure --profile mkse-demo
# Enter: Access Key ID, Secret Key, region: ap-southeast-1, output: json
export AWS_PROFILE=mkse-demo
export AWS_REGION=ap-southeast-1
```

### 2. Create KMS Customer Master Key

```bash
aws kms create-key --description "MKSE demo CMK" --region ap-southeast-1 --profile mkse-demo
# Save the KeyId and Arn from output
```

### 3. Create S3 Bucket

```bash
export BUCKET_NAME=mkse-demo-ciphertexts-<yourname>-$(date +%s)
aws s3api create-bucket --bucket $BUCKET_NAME --region ap-southeast-1 \
  --create-bucket-configuration LocationConstraint=ap-southeast-1 --profile mkse-demo

# Enable KMS encryption
aws s3api put-bucket-encryption --bucket $BUCKET_NAME --region ap-southeast-1 --profile mkse-demo \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"<KMS_KEY_ARN>"}}]}'
```

### 4. Create DynamoDB Table

```bash
aws dynamodb create-table \
  --table-name mkse-demo-index \
  --attribute-definitions AttributeName=label,AttributeType=S \
  --key-schema AttributeName=label,KeyType=HASH \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5 \
  --region ap-southeast-1 --profile mkse-demo
```

### 5. Create PRP Key in Secrets Manager

```bash
# Generate 32-byte hex PRP key locally
PRP_HEX=$(openssl rand -hex 32)

# Store in Secrets Manager
aws secretsmanager create-secret --name mkse-demo/prp-key \
  --description "PRP HMAC key for MKSE demo" \
  --secret-string "{\"prp_key\":\"$PRP_HEX\"}" \
  --region ap-southeast-1 --profile mkse-demo
```

### 6. Create IAM Role for Lambda Functions

Create a Lambda execution role `mkse-demo-lambda-role` with:
- Trust policy for `lambda.amazonaws.com`
- `AWSLambdaBasicExecutionRole` managed policy
- Custom policy with permissions for:
  - DynamoDB: `GetItem`, `Query`, `Scan` on `mkse-demo-index`
  - Secrets Manager: `GetSecretValue` on PRP key
  - S3: `GetObject` on bucket contents
  - KMS: `Decrypt` on CMK

Use the provided `mkse-lambda-policy.json` template (update ARNs and account ID).

### 7. Deploy Lambda Functions

#### Trapdoor Lambda
1. Create Lambda function `mkse-trapdoor` (Python 3.9/3.10)
2. Upload `trapdoor_lambda.py` code
3. Set environment variable: `PRP_SECRET_ARN=mkse-demo/prp-key`
4. Assign role: `mkse-demo-lambda-role`

#### Search Lambda
1. Create Lambda function `mkse-search`
2. Upload `search_lambda.py` code
3. Set environment variables:
   - `INDEX_TABLE_NAME=mkse-demo-index`
   - `S3_BUCKET=<BUCKET_NAME>`
4. Assign role: `mkse-demo-lambda-role`

### 8. Create API Gateway

Create an HTTP API with routes:
- `POST /trapdoor` → `mkse-trapdoor`
- `POST /search` → `mkse-search`

Deploy and note the Invoke URL.

## Usage

### Upload Documents (Data Owner)

1. Configure `owner_uploader.py` settings:
   - `AWS_PROFILE`, `AWS_REGION`, `KMS_KEY_ID`
   - `S3_BUCKET`, `DDB_TABLE`, `PRP_SECRET_ARN`

2. Place sample `.txt` files in `./docs/`
   

3. Run the uploader:
   > assuming the files to be uploaded are in `/docs`
```bash
AWS_PROFILE=mkse-demo AWS_REGION=ap-southeast-1 python3 owner_uploader.py \
  --docs_dir ./docs --top_k 4 --n_virtual 2
```

This will:
- Extract TF-IDF keywords and add virtual noise keywords
- Generate per-document AES-GCM data keys via KMS
- Encrypt documents and upload to S3 with encrypted key metadata
- Build obfuscated index in DynamoDB

### Search and Retrieve (Client)

1. **Generate trapdoor labels**:
```bash
curl -s -X POST "${API_BASE_URL}/trapdoor" \
  -H "Content-Type: application/json" \
  -d '{"keywords":["network"]}' | jq
```
> replace `network` with your `<keywords>`

2. **Search with labels**:
```bash
curl -s -X POST "${API_BASE_URL}/search" \
  -H "Content-Type: application/json" \
  -d '{"labels":["<label>"], "k":3}' | jq
```

3. **Download and decrypt results**:
```bash
AWS_PROFILE=mkse-demo python3 client_retrieve.py --label <label> --k 1
```

The client will:
- Query DynamoDB for document postings
- Download encrypted documents from S3
- Decrypt data keys using KMS
- Perform AES-GCM decryption locally
- Save plaintext results

## Security Considerations

⚠️ **Important**: This is a proof-of-concept for demonstration purposes.

For production deployment:
- Add authentication (Cognito/IAM authorizers) to API Gateway
- Implement least-privilege IAM policies
- Regular PRP key rotation and re-indexing
- Consider trapdoor unlinkability for query privacy
- Implement additional defenses against frequency analysis

## Clean Up

To avoid charges, delete all created resources:

```bash
# Delete Lambda functions and API Gateway via console
aws dynamodb delete-table --table-name mkse-demo-index --profile mkse-demo --region ap-southeast-1
aws s3 rm s3://$BUCKET_NAME --recursive --profile mkse-demo --region ap-southeast-1
aws s3api delete-bucket --bucket $BUCKET_NAME --profile mkse-demo --region ap-southeast-1
aws secretsmanager delete-secret --secret-id mkse-demo/prp-key --region ap-southeast-1 --profile mkse-demo --force-delete-without-recovery
# Schedule KMS key deletion via console (7-30 day waiting period)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

This implementation demonstrates searchable encryption techniques for educational purposes. Consider consulting cryptography experts for production systems handling sensitive data.
