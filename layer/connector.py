import base64
import boto3
import datetime
import gzip
import hashlib
import hmac
import io
import json
import logzero
import os
import re
import requests

logzero.json()
log = logzero.logger


def handle_log(event):

    exclusion_list = [
        "CloudTrail-Digest",
        "Config",
    ]

    customer_id = os.environ.get("CUSTOMER_ID", False)
    log_type = os.environ.get("LOG_TYPE", "ApplicationLog")
    shared_key = os.environ.get("SHARED_KEY", False)

    if customer_id is False or shared_key is False:
        log.error("customer_id, log_type, or shared_key is missing")
        return False

    client = boto3.resource("s3")

    # S3 events
    for record in event.get("Records", []):
        if "s3" in record:

            # Ignore records that are in the exclusion list
            if any(s in record["s3"]["object"]["key"] for s in exclusion_list):
                continue

            try:
                obj = client.Object(
                    record["s3"]["bucket"]["name"], record["s3"]["object"]["key"]
                )
                rawbody = io.BytesIO(obj.get()["Body"].read())
                log.info(
                    f"Downloaded {record['s3']['object']['key']} from {record['s3']['bucket']['name']}"
                )
                rawbody.seek(0)
                if record["s3"]["object"]["key"].endswith(".gz") or record["s3"][
                    "object"
                ]["key"].endswith(".gzip"):
                    rawbody = gzip.open(
                        rawbody, mode="rt", encoding="utf8", errors="ignore"
                    )
            except Exception as err:
                log.error(
                    f"Error downloading {record['s3']['object']['key']} from {record['s3']['bucket']['name']}"
                )
                log.error(err)
                return False

            lines = False

            # CloudTrail log
            if "CloudTrail" in record["s3"]["object"]["key"]:
                lines = parse_cloudtrail(rawbody)
                log_ops_user(rawbody)
                log_type = "AWSCloudTrail"

            # AWS ALB log
            if "elasticloadbalancing" in record["s3"]["object"]["key"]:
                lines = parse_alblog(rawbody)
                log_type = "AWSApplicationLoadBalancer"

            # GuardDuty log
            if "GuardDuty" in record["s3"]["object"]["key"]:
                lines = parse_guardduty(rawbody)
                log_type = "AWSGuardDuty"

            # VPC DNS query log
            if "vpcdnsquerylogs" in record["s3"]["object"]["key"]:
                lines = parse_vpcdnsquerylogs(rawbody)
                log_type = "AWSVPCDNSQueryLogs"

            # VPC Flow log
            if "vpcflowlogs" in record["s3"]["object"]["key"]:
                lines = parse_vpcflowlogs(rawbody)
                log_type = "AWSVPCFlowLogs"

            # WAF log
            if "aws-waf-logs" in record["s3"]["object"]["key"]:
                lines = parse_waf(rawbody)
                log_type = "AWSWebApplicationFirewall"

            if lines:
                log.info(f"Posting {len(lines)} lines")
                post_data(customer_id, shared_key, json.dumps(lines), log_type)
                return True

            log.warning(f"Handler received unrecognised record type: {record}")
            return True

    # SecurityHub events from EventBridge
    if "source" in event and event["source"] == "aws.securityhub":
        line = event["detail"]["findings"]
        log_type = "AWSSecurityHub"
        post_data(customer_id, shared_key, json.dumps(line), log_type)
        return True

    # If CloudWatch Subscription
    if "awslogs" in event:
        data = event["awslogs"]["data"]
        payload = gzip.decompress(base64.b64decode(data))
        log_type = "AWSCloudWatchLog"
        post_data(customer_id, shared_key, payload, log_type)
        return True

    # If application_log
    if "application_log" in event:
        line = event["application_log"]
        post_data(customer_id, shared_key, json.dumps(line), log_type)
        return True

    log.warning(f"Handler received unrecognised event: {event}")
    return True


def parse_alblog(body):
    headers = [
        "type",
        "time",
        "elb",
        "client:port",
        "backend:port",
        "request_processing_time",
        "backend_processing_time",
        "response_processing_time",
        "elb_status_code",
        "elb_target_status_code",
        "received_bytes",
        "sent_bytes",
        "request",
        "user_agent",
        "ssl_cipher",
        "ssl_protocol",
        "target_group_arn",
        "trace_id",
        "domain_name",
        "chosen_cert_arn",
        "matched_rule_priority",
        "request_creation_time",
        "actions_executed",
        "redirect_url",
        "error_reason",
        "target:port_list",
        "target_status_code_list",
        "classification",
        "classification_reason",
    ]
    lines = body.read().splitlines()
    return [
        dict(
            zip(
                headers,
                (
                    p.strip('"')
                    for p in re.split("( |\\\".*?\\\"|'.*?')", line)
                    if p.strip()
                ),
            )
        )
        for line in lines
    ]


def log_ops_user(body):
    body.seek(0)
    payload = body.read()
    if "ops1" in payload or "ops2" in payload:
        log.warning("Ops user found in CloudTrail log")
        return True
    return False


def parse_cloudtrail(body):
    lines = []
    payload = json.loads(body.read())
    for line in payload["Records"]:
        if len(line.keys()) == 0:
            continue
        lines.append(line)
    return lines


def parse_guardduty(body):
    return [json.loads(jline) for jline in body.read().splitlines()]


def parse_vpcdnsquerylogs(body):
    return [json.loads(jline) for jline in body.read().splitlines()]


def parse_vpcflowlogs(body):
    headers, *lines = body.read().splitlines()
    return [dict(zip(headers.split(" "), line.split(" "))) for line in lines]


def parse_waf(body):
    return [json.loads(jline) for jline in body.read().splitlines()]


def build_signature(
    customer_id, shared_key, date, content_length, method, content_type, resource
):
    x_headers = "x-ms-date:" + date
    string_to_hash = (
        method
        + "\n"
        + str(content_length)
        + "\n"
        + content_type
        + "\n"
        + x_headers
        + "\n"
        + resource
    )
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    authorization = "SharedKey {}:{}".format(customer_id, encoded_hash)
    return authorization


def post_data(customer_id, shared_key, body, log_type):
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)
    signature = build_signature(
        customer_id,
        shared_key,
        rfc1123date,
        content_length,
        method,
        content_type,
        resource,
    )
    uri = (
        "https://"
        + customer_id
        + ".ods.opinsights.azure.com"
        + resource
        + "?api-version=2016-04-01"
    )

    headers = {
        "content-type": content_type,
        "Authorization": signature,
        "Log-Type": log_type,
        "x-ms-date": rfc1123date,
    }

    response = requests.post(uri, data=body, headers=headers)
    if response.status_code >= 200 and response.status_code <= 299:
        log.info(f"Response code: {response.status_code}, log type: {log_type}")
        return True
    else:
        log.error(response.text)
        log.error(f"Response code: {response.status_code}, log type: {log_type}")
        return False
