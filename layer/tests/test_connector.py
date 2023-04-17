import io
import os
import pytest
import connector
import logzero
import json
from unittest.mock import patch


logzero.json()
log = logzero.logger

customer_id = "customer_id"
log_type = "log_type"
shared_key = "dGVzdCBrZXk="


def load_fixture(name):
    data = open(os.path.join(os.path.dirname(__file__), "fixtures", name), "rb")
    return data


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
def test_handle_log_no_s3_records():
    event = {"Records": [{"foo": "bar"}]}
    assert connector.handle_log(event) is True


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
def test_handle_log_fail_to_download_object():
    event = {"Records": [{"s3": {"bucket": {"name": "foo"}, "object": {"key": "bar"}}}]}
    assert connector.handle_log(event) is False


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
def test_handle_log_is_a_digest():
    event = {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": "foo"},
                    "object": {"key": "foo/CloudTrail-Digest/bar"},
                }
            }
        ]
    }
    assert connector.handle_log(event) is True


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
def test_handle_log_is_a_config():
    event = {
        "Records": [
            {"s3": {"bucket": {"name": "foo"}, "object": {"key": "foo/Config/bar"}}}
        ]
    }
    assert connector.handle_log(event) is True


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
@patch("connector.boto3")
@patch("connector.io")
@patch("connector.gzip")
@patch("connector.post_data")
def test_handle_log_succeeds_empty_records(
    mock_post_data, mock_gzip, mock_io, mock_boto3
):
    event = {"Records": [{"s3": {"bucket": {"name": "foo"}, "object": {"key": "bar"}}}]}
    mock_gzip.open().read.return_value = '{"Records": [{}]}'
    mock_post_data.return_value = True
    assert connector.handle_log(event) is True


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
@patch("connector.boto3")
@patch("connector.io")
@patch("connector.post_data")
def test_handle_log_succeeds_with_cloudtrail_data(mock_post_data, mock_io, mock_boto3):
    event = {
        "Records": [
            {"s3": {"bucket": {"name": "foo"}, "object": {"key": "CloudTrail.json.gz"}}}
        ]
    }
    mock_io.BytesIO.return_value = load_fixture("cloudtrail.json.gz")
    mock_post_data.return_value = True
    assert connector.handle_log(event) is True
    assert mock_post_data.call_count == 1


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
@patch("connector.boto3")
@patch("connector.io")
@patch("connector.post_data")
def test_handle_log_succeeds_with_guard_duty_data(mock_post_data, mock_io, mock_boto3):
    event = {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": "foo"},
                    "object": {"key": "GuardDuty.jsonl.json.gz"},
                }
            }
        ]
    }
    mock_io.BytesIO.return_value = load_fixture("guardduty.jsonl.json.gz")
    mock_post_data.return_value = True
    assert connector.handle_log(event) is True
    assert mock_post_data.call_count == 1


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
@patch("connector.boto3")
@patch("connector.io")
@patch("connector.post_data")
def test_handle_log_succeeds_with_vpc_flow_logs_data(
    mock_post_data, mock_io, mock_boto3
):
    event = {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": "foo"},
                    "object": {"key": "vpcflowlogs.jsonl.json.gz"},
                }
            }
        ]
    }
    mock_io.BytesIO.return_value = load_fixture("vpcflowlogs.log.gz")
    mock_post_data.return_value = True
    assert connector.handle_log(event) is True
    assert mock_post_data.call_count == 1


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
@patch("connector.boto3")
@patch("connector.io")
@patch("connector.post_data")
def test_handle_log_succeeds_with_vpc_dns_query_logs_data(
    mock_post_data, mock_io, mock_boto3
):
    event = {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": "foo"},
                    "object": {"key": "vpcdnsquerylogs.log.gz"},
                }
            }
        ]
    }
    mock_io.BytesIO.return_value = load_fixture("vpcdnsquery.log.gz")
    mock_post_data.return_value = True
    assert connector.handle_log(event) is True
    assert mock_post_data.call_count == 1


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
@patch("connector.boto3")
@patch("connector.io")
@patch("connector.post_data")
def test_handle_log_succeeds_with_application_loadbalancer_logs_data(
    mock_post_data, mock_io, mock_boto3
):
    event = {
        "Records": [
            {
                "s3": {
                    "bucket": {"name": "foo"},
                    "object": {"key": "elasticloadbalancing.jsonl.json.gz"},
                }
            }
        ]
    }
    mock_io.BytesIO.return_value = load_fixture("elasticloadbalancing.log.gz")
    mock_post_data.return_value = True
    assert connector.handle_log(event) is True
    assert mock_post_data.call_count == 1


@patch.dict(
    os.environ,
    {"CUSTOMER_ID": "foo", "SHARED_KEY": "foo"},
    clear=True,
)
@patch("connector.boto3")
@patch("connector.io")
@patch("connector.post_data")
def test_handle_log_succeeds_with_waf_logs_data(mock_post_data, mock_io, mock_boto3):
    event = {
        "Records": [
            {"s3": {"bucket": {"name": "foo"}, "object": {"key": "aws-waf-logs"}}}
        ]
    }
    mock_io.BytesIO.return_value = load_fixture("aws-waf-logs.jsonl")
    mock_post_data.return_value = True
    assert connector.handle_log(event) is True
    assert mock_post_data.call_count == 1


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
@patch("connector.boto3")
@patch("connector.io")
@patch("connector.post_data")
def test_handle_log_succeeds_with_cloudquery_log(mock_post_data, mock_io, mock_boto3):
    event = {
        "Records": [
            {"s3": {"bucket": {"name": "foo"}, "object": {"key": "cloudquery/aws_ecr_repositories/2023-04-16-22-03/f47fffa1-5335-4738-9546-8424b4b81061.json"}}}
        ]
    }
    mock_io.BytesIO.return_value = load_fixture("cloudquery.jsonl")
    mock_post_data.return_value = True
    assert connector.handle_log(event) is True
    assert mock_post_data.call_count == 1
    for each in json.loads(mock_post_data.call_args[0][2]):
        assert each["metadata_table"] == "aws_ecr_repositories"


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


@pytest.mark.parametrize(
    "test_input,expected", [("foo", False), ("fooops1bar", True), ("fooops2bar", True)]
)
def test_log_ops_user(test_input, expected):
    output = io.StringIO()
    output.write(test_input)
    assert connector.log_ops_user(output) == expected


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
