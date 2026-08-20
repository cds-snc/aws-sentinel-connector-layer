import base64
import datetime
import gzip
import hashlib
import hmac
import json
import logzero
import os
import requests

logzero.json()
log = logzero.logger

# LogsIngestionClient built on the first v2 delivery and reused across warm
# invocations. Building it costs a token acquisition, so this is not free.
_client = None


def handle_log(event):
    if not config_present():
        return False

    # SecurityHub events from EventBridge
    if "source" in event and event["source"] == "aws.securityhub":
        return deliver(event["detail"]["findings"], "AWSSecurityHub")

    # If CloudWatch Subscription
    if "awslogs" in event:
        data = event["awslogs"]["data"]
        payload = gzip.decompress(base64.b64decode(data))
        return deliver(payload, "AWSCloudWatchLog")

    # If application_log
    if "application_log" in event:
        log_type = os.environ.get("LOG_TYPE", "ApplicationLog")
        return deliver(event["application_log"], log_type)

    log.warning(f"Handler received unrecognised event: {event}")
    return True


# v1 (Data Collector API) and v2 (Logs Ingestion API) both live in this layer
# version. Which one runs is decided per-Lambda by the env vars it carries, so
# workstream D can move consumers one account at a time rather than all at once.
# A consumer that sets neither DCE_ENDPOINT nor DCR_CONFIG behaves exactly as it
# did before.
def v2_enabled():
    return bool(os.environ.get("DCE_ENDPOINT")) and bool(os.environ.get("DCR_CONFIG"))


def config_present():
    if v2_enabled():
        return True

    customer_id = os.environ.get("CUSTOMER_ID", False)
    shared_key = os.environ.get("SHARED_KEY", False)

    if customer_id is False or shared_key is False:
        log.error("customer_id, log_type, or shared_key is missing")
        return False

    return True


def deliver(data, log_type):
    if v2_enabled():
        return deliver_v2(data, log_type)
    return deliver_v1(data, log_type)


def deliver_v1(data, log_type):
    customer_id = os.environ.get("CUSTOMER_ID")
    shared_key = os.environ.get("SHARED_KEY")
    body = data if isinstance(data, (bytes, bytearray)) else json.dumps(data)
    post_data(customer_id, shared_key, body, log_type)
    return True


def deliver_v2(data, log_type):
    target = dcr_target(log_type)
    if target is None:
        return False

    records = to_records(data, log_type)
    if records is None:
        return False

    if not records:
        # CloudWatch sends a CONTROL_MESSAGE with no logEvents to validate a new
        # subscription filter. That is normal traffic, not an error — and
        # building a client for it would cost a token acquisition for nothing.
        log.info(f"Nothing to upload for log type: {log_type}")
        return True

    client = get_client(os.environ.get("DCE_ENDPOINT"))
    upload_data(client, target["dcrImmutableId"], target["streamName"], records)
    return True


# DCR_CONFIG maps a log type to the DCR that accepts it, as one JSON env var.
# Key names come verbatim from the `aws_dcr_config` Terraform output in
# cds-snc/sentinel; do not rename them here.
def dcr_target(log_type):
    try:
        config = json.loads(os.environ.get("DCR_CONFIG"))
    except ValueError:
        log.error("DCR_CONFIG is not valid JSON")
        return None

    target = config.get(log_type)
    if not isinstance(target, dict):
        log.error(f"No DCR_CONFIG entry for log type: {log_type}")
        return None

    if "dcrImmutableId" not in target or "streamName" not in target:
        log.error(
            f"DCR_CONFIG entry for {log_type} is missing dcrImmutableId or streamName"
        )
        return None

    return target


# The Logs Ingestion API takes a list of records matching the stream's declared
# columns, not an opaque body. Fields the stream does not declare are dropped at
# the stream declaration, before the DCR transform runs.
def to_records(data, log_type):
    if log_type == "AWSCloudWatchLog":
        return split_cloud_watch_envelope(data)

    if isinstance(data, list):
        return data

    return [data]


# Custom-AWSCloudWatchLog_v2_Input declares exactly these eight columns, and the
# declaration is the only protection against silent field loss: a DCR drops
# anything undeclared before the transform runs, and raw_data cannot carry it
# either, being pack(<declared columns>).
CLOUD_WATCH_ENVELOPE_FIELDS = (
    "owner",
    "logGroup",
    "logStream",
    "messageType",
    "subscriptionFilters",
)
CLOUD_WATCH_EVENT_FIELDS = ("id", "timestamp", "message")


# One record per logEvents[] entry, each carrying the envelope fields. The split
# has to happen here because a DCR transform cannot mv-expand, and posting the
# envelope whole would drop every id/timestamp/message as undeclared.
#
# Two things this deliberately does not do, both of which would lose data:
#
#   - It does not json.loads() the message. gc-articles is ~99% of CloudWatch
#     volume and its lines are plain text, so parsing-and-skipping — the shape of
#     gc-signin's fork — would drop nearly everything, silently. message is
#     declared a string; it stays whatever string CloudWatch sent.
#   - It does not convert timestamp. It is epoch milliseconds and the stream
#     declares it a long; the DCR transform does the arithmetic that makes it
#     TimeGenerated, because unixtime_milliseconds_todatetime() is not in the
#     subset of KQL a transform accepts.
def split_cloud_watch_envelope(payload):
    try:
        envelope = json.loads(payload)
    except ValueError:
        log.error("CloudWatch payload is not a JSON envelope")
        return None

    if not isinstance(envelope, dict):
        log.error("CloudWatch payload is not a JSON envelope")
        return None

    from_envelope = {
        field: envelope.get(field) for field in CLOUD_WATCH_ENVELOPE_FIELDS
    }

    records = []
    for event in envelope.get("logEvents") or []:
        record = dict(from_envelope)
        record.update({field: event.get(field) for field in CLOUD_WATCH_EVENT_FIELDS})
        records.append(record)

    return records


def get_client(endpoint):
    global _client
    if _client is None:
        _client = create_client(
            endpoint,
            client_id=os.environ.get("AZURE_CLIENT_ID"),
            tenant_id=os.environ.get("AZURE_TENANT_ID"),
            client_secret=os.environ.get("AZURE_CLIENT_SECRET"),
        )
    return _client


# Populate the env vars DefaultAzureCredential reads, for the client-secret flow.
def configure_azure_env(client_id, tenant_id, client_secret):
    if client_id:
        os.environ["AZURE_CLIENT_ID"] = client_id
    if tenant_id:
        os.environ["AZURE_TENANT_ID"] = tenant_id
    if client_secret:
        os.environ["AZURE_CLIENT_SECRET"] = client_secret


def cognito_configured():
    return bool(os.environ.get("COGNITO_IDENTITY_POOL_ID")) and bool(
        os.environ.get("COGNITO_DEVELOPER_PROVIDER_NAME")
    )


# Mint an OIDC token from Cognito for use as an Entra client assertion. The
# Lambda's IAM role is the only credential involved; nothing is stored.
#
# The developer user identifier is the managed identity's client id, which keeps
# Cognito's IdentityId mapping deterministic — and that IdentityId is the subject
# the federated credential matches on.
def get_cognito_assertion():
    import boto3

    response = boto3.client(
        "cognito-identity"
    ).get_open_id_token_for_developer_identity(
        IdentityPoolId=os.environ["COGNITO_IDENTITY_POOL_ID"],
        Logins={
            os.environ["COGNITO_DEVELOPER_PROVIDER_NAME"]: os.environ["AZURE_CLIENT_ID"]
        },
    )

    token = response.get("Token")
    if not token:
        raise RuntimeError("Cognito response did not include a Token")
    return token


def create_client(endpoint, client_id=None, tenant_id=None, client_secret=None):
    # Imported here, not at module scope, and the placement matters.
    # gc-signin-terraform builds its own layer.zip and rebuilds it by curling
    # this file alone, without requirements.txt, so its package directory has no
    # azure-*. A module-level import would raise on their cold start before
    # v2_enabled() ever runs, breaking them on the v1 path this change is meant
    # to leave alone. It also keeps the SDK off every v1 consumer's cold start.
    from azure.identity import ClientAssertionCredential, DefaultAzureCredential

    configure_azure_env(client_id, tenant_id, client_secret)

    # A secret wins when one is present, so a consumer can be moved to v2 with a
    # secret first and to federation later without a code change.
    if client_secret:
        credential = DefaultAzureCredential()
    elif cognito_configured() and client_id and tenant_id:
        # The assertion is passed as a callable, never a cached token: a
        # Cognito token is valid 15 minutes by default while the Entra token
        # lasts about an hour, so anything minted once at cold start is stale by
        # the first refresh on a warm container. ClientAssertionCredential
        # re-invokes func on every refresh, so each one mints a fresh token.
        credential = ClientAssertionCredential(
            tenant_id=tenant_id, client_id=client_id, func=get_cognito_assertion
        )
        log.info("Authenticating via Cognito federation, no stored secret")
    else:
        log.warning(
            "Neither a client secret nor Cognito federation is configured; "
            "DefaultAzureCredential will attempt its other credential types"
        )
        credential = DefaultAzureCredential()

    from azure.monitor.ingestion import LogsIngestionClient

    return LogsIngestionClient(endpoint=endpoint, credential=credential)


def upload_data(client, dcr_immutable_id, stream_name, logs):
    from azure.core.exceptions import HttpResponseError

    if not logs:
        log.warning("No data to send to Azure Monitor")
        return False

    try:
        # The SDK chunks to the API's 1 MB-per-call limit itself.
        client.upload(rule_id=dcr_immutable_id, stream_name=stream_name, logs=logs)
        log.info(f"Uploaded {len(logs)} entries, stream: {stream_name}")
        return True
    except HttpResponseError as e:
        log.error(f"Upload failed: {e}")
        return False


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

    response = requests.post(uri, data=body, headers=headers, timeout=(10))
    if response.status_code >= 200 and response.status_code <= 299:
        log.info(f"Response code: {response.status_code}, log type: {log_type}")
        return True
    else:
        log.error(response.text)
        log.error(f"Response code: {response.status_code}, log type: {log_type}")
        return False
