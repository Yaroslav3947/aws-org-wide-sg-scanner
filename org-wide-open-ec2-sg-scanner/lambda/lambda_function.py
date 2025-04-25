import boto3
import csv
import io
import os
import datetime
import json
from datetime import datetime as dt

def normalize_row(row):
    return json.dumps({
        "AccountId": row["AccountId"].strip(),
        "Region": row["Region"].strip(),
        "GroupId": row["GroupId"].strip(),
        "GroupName": row["GroupName"].strip(),
        "Port": int(row["Port"].strip()),
        "Protocol": row["Protocol"].strip().lower(),
        "CIDR": row["CIDR"].strip()
    }, sort_keys=True)

def csv_to_normalized_set(csv_content):
    lines = csv_content.strip().splitlines()
    reader = csv.DictReader(lines)
    normalized = set()
    for row in reader:
        normalized.add(normalize_row(row))
    return normalized

def format_alert_email(entries):
    lines = ["New open Security Group rules detected:\n"]
    for i, e in enumerate(entries, start=1):
        rule = json.loads(e)
        lines.append(f"Rule {i}:")
        lines.append(f"  AccountId  : {rule['AccountId']}")
        lines.append(f"  Region     : {rule['Region']}")
        lines.append(f"  GroupId    : {rule['GroupId']}")
        lines.append(f"  GroupName  : {rule['GroupName']}")
        lines.append(f"  Port       : {rule['Port']}")
        lines.append(f"  Protocol   : {rule['Protocol']}")
        lines.append(f"  CIDR       : {rule['CIDR']}")
        lines.append("")
    return "\n".join(lines)

def assume_role(account_id, role_name):
    sts = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    response = sts.assume_role(RoleArn=role_arn, RoleSessionName="OpenSGScanSession")
    creds = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"]
    )

def find_open_sg():
    s3 = boto3.client("s3")
    sns = boto3.client("sns")
    org = boto3.client("organizations")

    now = dt.utcnow()
    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    bucket = os.environ["S3_BUCKET"]
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")
    report_key = f"open_sg_reports/{timestamp}.csv"
    latest_key = "open_sg_reports/latest.csv"
    role_name = os.environ.get("CROSS_ACCOUNT_ROLE", "CorpReadOnlyAccess")

    findings = []

    paginator = org.get_paginator("list_accounts")
    accounts = []
    for page in paginator.paginate():
        accounts.extend(page["Accounts"])

    print(f"[DEBUG] Total accounts in organization: {len(accounts)}")
    active_accounts = [a for a in accounts if a["Status"] == "ACTIVE"]
    print(f"[DEBUG] Total ACTIVE accounts: {len(active_accounts)}")

    for acct in accounts:
        print(f"[DEBUG] Reviewing account: {acct['Id']} (status={acct['Status']})")
        if acct["Status"] != "ACTIVE":
            continue

        account_id = acct["Id"]
        print(f"[DEBUG] Scanning Account: {account_id}")
        try:
            session = assume_role(account_id, role_name)
            ec2_global = session.client("ec2")
            regions = [r["RegionName"] for r in ec2_global.describe_regions()["Regions"]]
            for region in regions:
                print(f"[DEBUG]  Region: {region}")
                ec2 = session.client("ec2", region_name=region)
                try:
                    sgs = ec2.describe_security_groups()["SecurityGroups"]
                except Exception as e:
                    print(f"[WARN] describe_security_groups failed in {account_id}/{region}: {e}")
                    continue

                for sg in sgs:
                    for perm in sg.get("IpPermissions", []):
                        from_port = perm.get("FromPort")
                        to_port = perm.get("ToPort")
                        ip_ranges = perm.get("IpRanges", [])
                        protocol = perm.get("IpProtocol", "").lower()

                        if from_port in [22, 3389] or to_port in [22, 3389]:
                            for cidr in ip_ranges:
                                cidr_ip = cidr.get("CidrIp")
                                if cidr_ip == "0.0.0.0/0":
                                    findings.append({
                                        "AccountId": str(account_id),
                                        "Region": region,
                                        "GroupId": sg["GroupId"],
                                        "GroupName": sg.get("GroupName", ""),
                                        "Port": int(from_port) if from_port is not None else -1,
                                        "Protocol": protocol,
                                        "CIDR": cidr_ip
                                    })
        except Exception as e:
            print(f"[WARN] Failed in account {account_id}: {e}")
            continue

    csv_buffer = io.StringIO()
    writer = csv.DictWriter(csv_buffer, fieldnames=["AccountId", "Region", "GroupId", "GroupName", "Port", "Protocol", "CIDR"])
    writer.writeheader()
    for row in findings:
        writer.writerow({
            "AccountId": str(row["AccountId"]),
            "Region": row["Region"],
            "GroupId": row["GroupId"],
            "GroupName": row["GroupName"],
            "Port": str(row["Port"]),
            "Protocol": row["Protocol"],
            "CIDR": row["CIDR"]
        })
    csv_data = csv_buffer.getvalue()

    try:
        response = s3.get_object(Bucket=bucket, Key=latest_key)
        previous_csv = response["Body"].read().decode("utf-8")
        previous = csv_to_normalized_set(previous_csv)
    except Exception:
        previous = set()

    current = csv_to_normalized_set(csv_data)
    new_entries = current - previous

    s3.put_object(Bucket=bucket, Key=report_key, Body=csv_data)
    s3.put_object(Bucket=bucket, Key=latest_key, Body=csv_data)

    if new_entries:
        message_body = format_alert_email(new_entries)
        if sns_topic_arn:
            try:
                sns.publish(
                    TopicArn=sns_topic_arn,
                    Subject="[ALERT] New open Security Group rules",
                    Message=message_body
                )
            except Exception:
                pass

def lambda_handler(event, context):
    find_open_sg()
