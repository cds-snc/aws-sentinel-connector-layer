import ast
import base64
import gzip
import json
import os
import pathlib
import connector
from unittest.mock import patch

customer_id = "customer_id"
log_type = "log_type"
shared_key = "dGVzdCBrZXk="


@patch.dict(os.environ, {"LOG_TYPE": "foo", "SHARED_KEY": "foo"}, clear=True)
def test_handle_log_customer_id_not_provided():
    event = {}
    assert connector.handle_log(event) is False


@patch.dict(
    os.environ,
    {
        "CUSTOMER_ID": "foo",
    },
    clear=True,
)
def test_handle_log_shared_key_not_provided():
    event = {}
    assert connector.handle_log(event) is False


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
def test_handle_log_no_records():
    event = {}
    assert connector.handle_log(event) is True


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
@patch("connector.post_data")
def test_handle_log_succeeds_with_securityhub_data(mock_post_data):
    event = {
        "source": "aws.securityhub",
        "detail": {
            "findings": {
                "id": "123456789",
            }
        },
    }
    mock_post_data.return_value = True
    assert connector.handle_log(event) is True
    assert mock_post_data.call_count == 1


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
@patch("connector.post_data")
def test_handle_log_succeeds_with_cloud_watch_log(mock_post_data):
    event = {
        "awslogs": {
            "data": "H4sIAAAAAAAAAK2QTWvcMBCG/4oRPS5Y8yGNlFMd6iyBtpSub+lStLE2GNb2xvY2lDT/vbMNvRT21MAgDe+MZh69z6bP85wecvPzmM2V+VA11fdP9WZTrWuzMuPTkCeVLYhEGxEEncqH8WE9jaejVsr0NJeH1O/aVN6M42txs0w59VpFi1gClHrevftYNfWm2e4RwAcPFFrHMYe4T+SSQ/IRiGmnI+bTbr6fuuPSjcNNd1jyNJurO3N+fvt5bbZ/ltQ/8rCc9WfTtbqLBJGsRHJWiNmxQxZg79Fb4hDBWw/BegKHEZkR2LkgpPuWTl1YUq8fAq8YbL11AXD11x0dX7V9NxTVl9tiyo8nbS/WdVNcV1+L/Ti+36XpV5pbjcfX69tgXlb/kvnzWmInjiITUhSHEh0DCgBacqyJU0wQzeIFMk8kb02mRkXPHMiqcd4LCgd0appixhCDiApeXdR+CHCJTJjenCwKiyBbDNaSBoH1apOm0YoEL4BMYiGKgJULZOrv/5JtX34DDTXoyi0DAAA="
        }
    }
    mock_post_data.return_value = True
    assert connector.handle_log(event) is True
    assert mock_post_data.call_count == 1


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
@patch("connector.post_data")
def test_handle_log_succeeds_with_application_log_data(mock_post_data):
    event = {
        "application_log": {
            "foo": "bar",
        }
    }
    mock_post_data.return_value = True
    assert connector.handle_log(event) is True
    assert mock_post_data.call_count == 1


def test_build_signature():
    body = "{}"
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    date = "Sun, 21 Nov 2021 18:35:52 GMT"
    content_length = len(body)

    expected = "SharedKey customer_id:bSu2KGHkG5BkSq5WqYTlxfTlBpYFi+TgwYEQaZ/PwN8="
    assert (
        connector.build_signature(
            customer_id,
            shared_key,
            date,
            content_length,
            method,
            content_type,
            resource,
        )
        == expected
    )


@patch("connector.requests")
def test_post_data_success(mock_requests):
    body = "{}"
    log_type = "test_log_type"

    mock_requests.post.return_value.status_code = 200

    assert connector.post_data(customer_id, shared_key, body, log_type)


@patch("connector.requests")
def test_post_data_failure(mock_requests):
    body = "{}"
    log_type = "test_log_type"

    mock_requests.post.return_value.status_code = 400

    assert connector.post_data(customer_id, shared_key, body, log_type) is False


# --- v2 (Logs Ingestion API) --------------------------------------------------

DCE_ENDPOINT = (
    "https://dce-sentinel-forwarder-v2-153n.canadacentral-1.ingest.monitor.azure.com"
)

DCR_CONFIG = json.dumps(
    {
        "AWSSecurityHub": {
            "dcrImmutableId": "dcr-securityhub",
            "streamName": "Custom-AWSSecurityHub_v2_Input",
        },
        "AWSCloudWatchLog": {
            "dcrImmutableId": "dcr-cloudwatch",
            "streamName": "Custom-AWSCloudWatchLog_v2_Input",
        },
        "ApplicationLog": {
            "dcrImmutableId": "dcr-application",
            "streamName": "Custom-ApplicationLog_v2_Input",
        },
    }
)

V2_ENV = {"DCE_ENDPOINT": DCE_ENDPOINT, "DCR_CONFIG": DCR_CONFIG}

CLOUD_WATCH_EVENT = {
    "awslogs": {
        "data": "H4sIAAAAAAAAAK2QTWvcMBCG/4oRPS5Y8yGNlFMd6iyBtpSub+lStLE2GNb2xvY2lDT/vbMNvRT21MAgDe+MZh69z6bP85wecvPzmM2V+VA11fdP9WZTrWuzMuPTkCeVLYhEGxEEncqH8WE9jaejVsr0NJeH1O/aVN6M42txs0w59VpFi1gClHrevftYNfWm2e4RwAcPFFrHMYe4T+SSQ/IRiGmnI+bTbr6fuuPSjcNNd1jyNJurO3N+fvt5bbZ/ltQ/8rCc9WfTtbqLBJGsRHJWiNmxQxZg79Fb4hDBWw/BegKHEZkR2LkgpPuWTl1YUq8fAq8YbL11AXD11x0dX7V9NxTVl9tiyo8nbS/WdVNcV1+L/Ti+36XpV5pbjcfX69tgXlb/kvnzWmInjiITUhSHEh0DCgBacqyJU0wQzeIFMk8kb02mRkXPHMiqcd4LCgd0appixhCDiApeXdR+CHCJTJjenCwKiyBbDNaSBoH1apOm0YoEL4BMYiGKgJULZOrv/5JtX34DDTXoyi0DAAA="
    }
}


def setup_function():
    # The client is cached for warm-invocation reuse; clear it between tests.
    connector._client = None


# The one regression guard for gc-signin-terraform, which rebuilds its own
# layer.zip by curling this file without requirements.txt. A module-level azure
# import raises on their cold start, before v2_enabled() can route them to v1.
def test_azure_sdk_is_not_imported_at_module_scope():
    source = pathlib.Path(connector.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported = []
    for node in tree.body:
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")

    assert not [name for name in imported if name.startswith("azure")]


@patch.dict(os.environ, {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"}, clear=True)
def test_v2_disabled_without_env_vars():
    assert connector.v2_enabled() is False


@patch.dict(os.environ, {"DCE_ENDPOINT": DCE_ENDPOINT}, clear=True)
def test_v2_disabled_without_dcr_config():
    assert connector.v2_enabled() is False


@patch.dict(os.environ, {"DCR_CONFIG": DCR_CONFIG}, clear=True)
def test_v2_disabled_without_dce_endpoint():
    assert connector.v2_enabled() is False


@patch.dict(os.environ, V2_ENV, clear=True)
def test_v2_enabled_with_both_env_vars():
    assert connector.v2_enabled() is True


# v1 consumers must be untouched by this change: no v2 env vars means the
# SharedKey sink, even with azure credentials sitting in the environment.
@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo", "AZURE_CLIENT_ID": "bar"},
    clear=True,
)
@patch("connector.upload_data")
@patch("connector.post_data")
def test_v1_still_used_when_v2_env_absent(mock_post_data, mock_upload_data):
    event = {"source": "aws.securityhub", "detail": {"findings": {"id": "123"}}}
    assert connector.handle_log(event) is True
    assert mock_post_data.call_count == 1
    assert mock_upload_data.call_count == 0


# B3 gates its split to v2, so v1 keeps posting the envelope whole and byte-identical.
@patch.dict(os.environ, {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"}, clear=True)
@patch("connector.post_data")
def test_v1_cloud_watch_posts_the_raw_envelope(mock_post_data):
    assert connector.handle_log(CLOUD_WATCH_EVENT) is True
    body = mock_post_data.call_args[0][2]
    assert isinstance(body, bytes)
    assert json.loads(body)["logEvents"]


@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_securityhub_uploads_findings(mock_upload_data, mock_get_client):
    findings = [{"Id": "finding-1"}, {"Id": "finding-2"}]
    event = {"source": "aws.securityhub", "detail": {"findings": findings}}

    assert connector.handle_log(event) is True
    assert mock_upload_data.call_count == 1

    _client, rule_id, stream_name, logs = mock_upload_data.call_args[0]
    assert rule_id == "dcr-securityhub"
    assert stream_name == "Custom-AWSSecurityHub_v2_Input"
    assert logs == findings


@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_application_log_uploads_one_record(mock_upload_data, mock_get_client):
    event = {"application_log": {"foo": "bar"}}

    assert connector.handle_log(event) is True

    _client, rule_id, stream_name, logs = mock_upload_data.call_args[0]
    assert rule_id == "dcr-application"
    assert stream_name == "Custom-ApplicationLog_v2_Input"
    assert logs == [{"foo": "bar"}]


# --- B3: the CloudWatch sender-side split ------------------------------------

# The columns Custom-AWSCloudWatchLog_v2_Input declares, and the whole contract.
# A DCR drops undeclared fields at the stream declaration, before the transform
# runs, so this list is the only protection against silent field loss.
CLOUD_WATCH_STREAM_COLUMNS = {
    "owner",
    "logGroup",
    "logStream",
    "messageType",
    "subscriptionFilters",
    "id",
    "timestamp",
    "message",
}


def cloud_watch_event(log_events, **envelope):
    """Build a subscription-filter event the way CloudWatch Logs delivers one."""
    payload = {
        "messageType": "DATA_MESSAGE",
        "owner": "017790921725",
        "logGroup": "/aws/lambda/Foo",
        "logStream": "2022/11/22/[$LATEST]f211686138d549e89fa35a523691343b",
        "subscriptionFilters": ["TESTING"],
        "logEvents": log_events,
    }
    payload.update(envelope)
    data = base64.b64encode(gzip.compress(json.dumps(payload).encode())).decode()
    return {"awslogs": {"data": data}}


def uploaded_records(mock_upload_data):
    _client, _rule_id, _stream_name, logs = mock_upload_data.call_args[0]
    return logs


# The fan-out is the point: sampled traffic is 4.6 log events per envelope, so a
# split that emitted one record per envelope would still look like a success.
@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_cloud_watch_emits_one_record_per_log_event(
    mock_upload_data, mock_get_client
):
    assert connector.handle_log(CLOUD_WATCH_EVENT) is True

    records = uploaded_records(mock_upload_data)
    assert len(records) == 4
    assert [r["id"] for r in records] == [
        "37223079350734454524714662603489160618063152924421455873",
        "37223079362442345753943239752795412711203542715061174279",
        "37223079371496448304546672748258914329898777486489223181",
        "37223079379747724028003003310627130090778671243701977107",
    ]


# Live traffic averages ~4.2 log events per envelope and peaks at 211 (measured
# over 81,989 envelopes in 24 h). Pin the relationship as linear, above that
# peak, so a cap or a slice — which every fixture-sized test above would still
# pass — cannot truncate the large envelopes silently.
@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_cloud_watch_fan_out_is_linear_in_log_events(
    mock_upload_data, mock_get_client
):
    events = [
        {"id": str(n), "timestamp": 1669140605812 + n, "message": f"line {n}"}
        for n in range(250)
    ]

    assert connector.handle_log(cloud_watch_event(events)) is True

    records = uploaded_records(mock_upload_data)
    assert len(records) == 250
    assert [r["id"] for r in records] == [str(n) for n in range(250)]


@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_cloud_watch_uploads_to_the_cloud_watch_dcr(
    mock_upload_data, mock_get_client
):
    assert connector.handle_log(CLOUD_WATCH_EVENT) is True

    _client, rule_id, stream_name, _logs = mock_upload_data.call_args[0]
    assert rule_id == "dcr-cloudwatch"
    assert stream_name == "Custom-AWSCloudWatchLog_v2_Input"


@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_cloud_watch_carries_the_envelope_fields_onto_every_record(
    mock_upload_data, mock_get_client
):
    event = cloud_watch_event(
        [
            {"id": "1", "timestamp": 1669140605812, "message": "first"},
            {"id": "2", "timestamp": 1669140606337, "message": "second"},
        ]
    )
    assert connector.handle_log(event) is True

    for record in uploaded_records(mock_upload_data):
        assert record["owner"] == "017790921725"
        assert record["logGroup"] == "/aws/lambda/Foo"
        assert (
            record["logStream"]
            == "2022/11/22/[$LATEST]f211686138d549e89fa35a523691343b"
        )
        assert record["messageType"] == "DATA_MESSAGE"
        assert record["subscriptionFilters"] == ["TESTING"]


@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_cloud_watch_carries_the_event_fields(mock_upload_data, mock_get_client):
    event = cloud_watch_event(
        [{"id": "abc", "timestamp": 1669140605812, "message": "a line"}]
    )
    assert connector.handle_log(event) is True

    (record,) = uploaded_records(mock_upload_data)
    assert record["id"] == "abc"
    # Epoch milliseconds, as a number — the DCR transform does the arithmetic
    # conversion to TimeGenerated, so a pre-formatted string would break it.
    assert record["timestamp"] == 1669140605812
    assert isinstance(record["timestamp"], int)
    assert record["message"] == "a line"


# Do not copy gc-signin's split: theirs json.loads() each message and skips
# anything non-JSON. gc-articles is ~99% of CloudWatch volume and its lines are
# plain text, so every one of them would be dropped silently.
@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_cloud_watch_keeps_plain_text_and_json_messages_alike(
    mock_upload_data, mock_get_client
):
    plain = '127.0.0.1 -  11/Aug/2026:17:47:43 +0000 "GET /index.php" 302'
    structured = '{"level":"info","msg":"hello"}'
    event = cloud_watch_event(
        [
            {"id": "1", "timestamp": 1669140605812, "message": plain},
            {"id": "2", "timestamp": 1669140606337, "message": structured},
        ]
    )
    assert connector.handle_log(event) is True

    records = uploaded_records(mock_upload_data)
    assert [r["message"] for r in records] == [plain, structured]
    # A JSON-looking line stays an unparsed string: the stream declares message
    # as a string, and parsing it here would drop it as a type mismatch.
    assert isinstance(records[1]["message"], str)


@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_cloud_watch_records_declare_exactly_the_stream_columns(
    mock_upload_data, mock_get_client
):
    assert connector.handle_log(CLOUD_WATCH_EVENT) is True

    for record in uploaded_records(mock_upload_data):
        assert set(record) == CLOUD_WATCH_STREAM_COLUMNS


# CloudWatch sends a CONTROL_MESSAGE with no logEvents to validate a new
# subscription filter. It is normal traffic, not an error — and building a client
# for it would cost a token acquisition for nothing.
@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_cloud_watch_control_message_uploads_nothing(
    mock_upload_data, mock_get_client
):
    event = cloud_watch_event([], messageType="CONTROL_MESSAGE")

    assert connector.handle_log(event) is True
    assert mock_upload_data.call_count == 0
    assert mock_get_client.call_count == 0


@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_cloud_watch_rejects_a_payload_that_is_not_an_envelope(
    mock_upload_data, mock_get_client
):
    data = base64.b64encode(gzip.compress(b"not json")).decode()

    assert connector.handle_log({"awslogs": {"data": data}}) is False
    assert mock_upload_data.call_count == 0


# Valid JSON that is not an object: rejected rather than raising, so one bad
# payload cannot fail an invocation that carries nothing else.
@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_cloud_watch_rejects_json_that_is_not_an_object(
    mock_upload_data, mock_get_client
):
    data = base64.b64encode(gzip.compress(b'["not", "an", "envelope"]')).decode()

    assert connector.handle_log({"awslogs": {"data": data}}) is False
    assert mock_upload_data.call_count == 0


@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.get_client")
@patch("connector.upload_data")
def test_v2_unmapped_log_type_does_not_upload(mock_upload_data, mock_get_client):
    with patch.dict(os.environ, {"LOG_TYPE": "NotInTheMap"}):
        assert connector.handle_log({"application_log": {"foo": "bar"}}) is False
    assert mock_upload_data.call_count == 0


@patch.dict(
    os.environ,
    {"DCE_ENDPOINT": DCE_ENDPOINT, "DCR_CONFIG": "not json"},
    clear=True,
)
def test_dcr_target_rejects_invalid_json():
    assert connector.dcr_target("AWSSecurityHub") is None


@patch.dict(
    os.environ,
    {
        "DCE_ENDPOINT": DCE_ENDPOINT,
        "DCR_CONFIG": json.dumps({"AWSSecurityHub": {"streamName": "Custom-x"}}),
    },
    clear=True,
)
def test_dcr_target_rejects_incomplete_entry():
    assert connector.dcr_target("AWSSecurityHub") is None


@patch.dict(os.environ, V2_ENV, clear=True)
def test_dcr_target_returns_both_fields():
    target = connector.dcr_target("AWSCloudWatchLog")
    assert target["dcrImmutableId"] == "dcr-cloudwatch"
    assert target["streamName"] == "Custom-AWSCloudWatchLog_v2_Input"


@patch.dict(os.environ, V2_ENV, clear=True)
@patch("connector.create_client")
def test_get_client_is_cached_across_invocations(mock_create_client):
    first = connector.get_client(DCE_ENDPOINT)
    second = connector.get_client(DCE_ENDPOINT)
    assert first is second
    assert mock_create_client.call_count == 1


@patch.dict(os.environ, {}, clear=True)
def test_configure_azure_env_sets_client_secret_variables():
    connector.configure_azure_env("client", "tenant", "secret")
    assert os.environ["AZURE_CLIENT_ID"] == "client"
    assert os.environ["AZURE_TENANT_ID"] == "tenant"
    assert os.environ["AZURE_CLIENT_SECRET"] == "secret"


@patch.dict(os.environ, {}, clear=True)
def test_configure_azure_env_without_secret_sets_no_secret():
    connector.configure_azure_env("client", "tenant", None)
    assert "AZURE_CLIENT_SECRET" not in os.environ


COGNITO_ENV = {
    "AZURE_CLIENT_ID": "client",
    "AZURE_TENANT_ID": "tenant",
    "COGNITO_IDENTITY_POOL_ID": "ca-central-1:00000000-0000-0000-0000-000000000000",
    "COGNITO_DEVELOPER_PROVIDER_NAME": "azure-sentinel-access",
}


# A secret wins when present, so a consumer can move to v2 with a secret first
# and to federation later without a code change.
@patch.dict(os.environ, dict(COGNITO_ENV, AZURE_CLIENT_SECRET="s"), clear=True)
@patch("azure.monitor.ingestion.LogsIngestionClient")
@patch("azure.identity.ClientAssertionCredential")
@patch("azure.identity.DefaultAzureCredential")
def test_create_client_prefers_the_secret(mock_default, mock_assertion, mock_lic):
    connector.create_client(DCE_ENDPOINT, "client", "tenant", "s")
    assert mock_default.call_count == 1
    assert mock_assertion.call_count == 0


@patch.dict(os.environ, COGNITO_ENV, clear=True)
@patch("azure.monitor.ingestion.LogsIngestionClient")
@patch("azure.identity.ClientAssertionCredential")
@patch("azure.identity.DefaultAzureCredential")
def test_create_client_federates_when_no_secret(mock_default, mock_assertion, mock_lic):
    connector.create_client(DCE_ENDPOINT, "client", "tenant", None)
    assert mock_assertion.call_count == 1
    assert mock_default.call_count == 0

    kwargs = mock_assertion.call_args[1]
    assert kwargs["tenant_id"] == "tenant"
    assert kwargs["client_id"] == "client"
    # The callable, not a token: it is re-invoked on every refresh, so a Cognito
    # token minted at cold start cannot go stale on a warm container.
    assert kwargs["func"] is connector.get_cognito_assertion


@patch.dict(os.environ, {"AZURE_CLIENT_ID": "client"}, clear=True)
@patch("azure.monitor.ingestion.LogsIngestionClient")
@patch("azure.identity.ClientAssertionCredential")
@patch("azure.identity.DefaultAzureCredential")
def test_create_client_falls_back_with_neither(mock_default, mock_assertion, mock_lic):
    connector.create_client(DCE_ENDPOINT, "client", None, None)
    assert mock_default.call_count == 1
    assert mock_assertion.call_count == 0


@patch.dict(os.environ, COGNITO_ENV, clear=True)
def test_get_cognito_assertion_returns_the_token():
    with patch("boto3.client") as mock_boto:
        mock_boto.return_value.get_open_id_token_for_developer_identity.return_value = {
            "Token": "the-jwt"
        }
        assert connector.get_cognito_assertion() == "the-jwt"

    call = mock_boto.return_value.get_open_id_token_for_developer_identity.call_args[1]
    assert call["IdentityPoolId"] == COGNITO_ENV["COGNITO_IDENTITY_POOL_ID"]
    # The developer user identifier is the managed identity's client id, which
    # keeps Cognito's IdentityId — the federated credential's subject — stable.
    assert call["Logins"] == {"azure-sentinel-access": "client"}


@patch.dict(os.environ, COGNITO_ENV, clear=True)
def test_get_cognito_assertion_raises_without_a_token():
    with patch("boto3.client") as mock_boto:
        mock_boto.return_value.get_open_id_token_for_developer_identity.return_value = (
            {}
        )
        try:
            connector.get_cognito_assertion()
            assert False, "expected RuntimeError"
        except RuntimeError:
            pass


@patch.dict(os.environ, {}, clear=True)
def test_cognito_not_configured_without_env():
    assert connector.cognito_configured() is False


@patch.dict(os.environ, COGNITO_ENV, clear=True)
def test_cognito_configured_with_env():
    assert connector.cognito_configured() is True


def test_upload_data_success():
    client = patch("connector.get_client").start()
    client.upload.return_value = None
    assert connector.upload_data(client, "dcr-1", "Custom-x", [{"a": 1}]) is True
    client.upload.assert_called_once_with(
        rule_id="dcr-1", stream_name="Custom-x", logs=[{"a": 1}]
    )
    patch.stopall()


def test_upload_data_with_no_records():
    client = patch("connector.get_client").start()
    assert connector.upload_data(client, "dcr-1", "Custom-x", []) is False
    assert client.upload.call_count == 0
    patch.stopall()


def test_upload_data_failure():
    from azure.core.exceptions import HttpResponseError

    client = patch("connector.get_client").start()
    client.upload.side_effect = HttpResponseError("rejected")
    assert connector.upload_data(client, "dcr-1", "Custom-x", [{"a": 1}]) is False
    patch.stopall()
