# EC2 Open SG Scanner (Org-Wide)

Scans EC2 security groups across **all AWS Organization accounts** for ingress from `0.0.0.0/0` on ports:
- 22 (SSH)
- 3389 (RDP)

---

##  How It Works

- Lambda runs **from the root account**
- Uses `organizations:ListAccounts` to enumerate all member accounts
- Assumes cross-account IAM role `CorpReadOnlyAccess` in each account
- Analyzes attached Security Groups for EC2 instances only
- Sends an **email to SOC analyst** every 24 hours **only if new open SG rules are detected**
- Stores daily CSV scan reports in an S3 bucket
- Scheduled via **EventBridge**, notifies via **SNS**, code runs in **Lambda**

> The `CorpReadOnlyAccess` role must be deployed in **every member account** and trust the root account.

---

##  Deployment Steps

1. **Create an S3 Bucket** in the root account (e.g. `org-wide-sg-reports`)
2. **Upload Lambda ZIP** to the bucket (e.g. `lambda_function.zip`)
3. **Deploy CloudFormation stack** with required params:

```bash
aws cloudformation create-stack \
  --stack-name org-sg-ec2-stack \
  --template-body file://ec2_sg_template.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=S3BucketName,ParameterValue=org-wide-open-sg-reports \
    ParameterKey=SNSTopicEmail,ParameterValue=your-email@example.com