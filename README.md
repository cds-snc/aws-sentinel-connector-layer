# AWS Sentinel connection layer

This repository contains the code for an AWS lambda layer that is used in a custom terraform module here - https://github.com/cds-snc/terraform-modules/tree/main/sentinel_forwarder
which forwards AWS logs to an Azure LogAnalytics Workspace and ultimately Microsoft Sentinel. Please see the module for a reference implementation.

The code can handle the following types of logs

- SecurityHub (via EventBridge)
- CloudWatch Logs (via a subscription filter)
- Generic application json logs

### Removed: the S3 log types

The layer used to parse CloudTrail, Load balancer, VPC flow, VPC DNS query, WAF ACL, GuardDuty and
CloudQuery logs, all delivered by S3 `ObjectCreated` notifications. **All of it was dead code and
was removed in 2026-08.** No consumer had triggered the S3 path for some time: the
`sentinel_forwarder` module gates its bucket notification on `var.s3_sources`, and no repository set
it. Verified against 90 days of Log Analytics `Usage` data — the corresponding `_CL` tables were
either empty or had never existed.

The two sources that were real moved to native Sentinel connectors rather than this layer:

- **CloudTrail** → the Amazon Web Services S3 connector, into `AWSCloudTrail`.
- **GuardDuty** → the same connector, into `AWSGuardDuty`, in
  [cds-aws-lz#449](https://github.com/cds-snc/cds-aws-lz/pull/449).

If you need one of the removed parsers back, prefer a native connector. Recovering the old code is
possible but note that both S3 log types were removed *because* a native connector had already
claimed the same bucket notification, and two `aws_s3_bucket_notification` resources on one bucket
silently overwrite each other.

You will need to add your Log Analytics Workspace Customer ID and Shared Key. AWS logs are automatically assigned a LogType.
Custom application logs are given the log type defined through the `var.log_type`. They also need to be nested inside a json
object with the key, `application_log`. ex: `{'application_log': {'foo': 'bar'}}` for the layer code to forward it to Azure Sentinel.

**`LOG_TYPE` applies to v1 only.** On v1 the `Log-Type` header *is* the destination table, so
`var.log_type` still names it. On v2 the destination comes from `DCR_CONFIG`, keyed by log type, and
`LOG_TYPE` selects nothing — an `application_log` event dispatches on the fixed key
`ApplicationLog`, and is refused if `DCR_CONFIG` has no entry under it.

### Two ingestion APIs in one layer version

Microsoft is retiring the Data Collector API. This layer supports both it and its replacement, the
Logs Ingestion API, and **picks between them from the environment variables the Lambda carries** —
so consumers can migrate one at a time instead of all at once.

| | v1 — Data Collector API | v2 — Logs Ingestion API |
| --- | --- | --- |
| Selected when | `DCE_ENDPOINT` / `DCR_CONFIG` are absent | **both** `DCE_ENDPOINT` and `DCR_CONFIG` are set |
| Config | `CUSTOMER_ID`, `SHARED_KEY` | `DCE_ENDPOINT`, `DCR_CONFIG`, plus Azure credentials |
| Auth | SharedKey HMAC | Entra, via `DefaultAzureCredential` |
| Destination | `<LogType>_CL`, workspace-wide | a DCR stream, per log type |

`DCR_CONFIG` is one JSON object mapping a log type to the DCR that accepts it. Populate it from the
`aws_dcr_config` Terraform output rather than by hand:

```json
{
  "AWSSecurityHub":   { "dcrImmutableId": "dcr-…", "streamName": "Custom-AWSSecurityHub_v2_Input" },
  "AWSCloudWatchLog": { "dcrImmutableId": "dcr-…", "streamName": "Custom-AWSCloudWatchLog_v2_Input" }
}
```

#### CloudWatch under v2: one record per log event

v1 posted the whole subscription envelope, so everything inside `logEvents` arrived as one opaque
`logEvents_s` string that nothing could query without `parse_json`. Under v2 the layer splits the
envelope **sender-side**: one record per `logEvents[]` entry, each carrying the envelope fields.

| From the envelope, onto every record | From each `logEvents[]` entry |
| --- | --- |
| `owner`, `logGroup`, `logStream`, `messageType`, `subscriptionFilters` | `id`, `timestamp`, `message` |

Those eight fields are exactly what `Custom-AWSCloudWatchLog_v2_Input` declares, and the declaration
is the only protection against silent loss — a DCR drops undeclared fields before its transform
runs. Three properties of the split are load-bearing:

- **`message` stays an unparsed string.** Most CloudWatch volume is plain text, not JSON, so parsing
  it and skipping what fails to parse would drop nearly all of it silently.
- **`timestamp` stays epoch milliseconds.** The DCR transform converts it to `TimeGenerated`
  arithmetically, because `unixtime_milliseconds_todatetime()` is not in the subset of KQL a
  transform accepts.
- **A `CONTROL_MESSAGE` envelope uploads nothing** and is not an error. CloudWatch sends one to
  validate a new subscription filter; it carries no `logEvents`, and building a client for it would
  cost a token acquisition for nothing.

The split is gated to v2. On v1 the envelope is posted whole and byte-identical, exactly as before.

#### v2 authentication

Two flows, chosen by which variables are set. **A client secret wins when one is present**, so a
consumer can move to v2 with a secret first and to federation later without a code change.

| | Client secret | Cognito federation (no stored secret) |
| --- | --- | --- |
| Variables | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET` | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `COGNITO_IDENTITY_POOL_ID`, `COGNITO_DEVELOPER_PROVIDER_NAME` |
| Credential | `DefaultAzureCredential` | `ClientAssertionCredential` |

Under federation the Lambda's IAM role is the only credential. It calls
`cognito-identity:GetOpenIdTokenForDeveloperIdentity`, and the resulting OIDC JWT is presented to
Entra as a client assertion for a user-assigned managed identity whose federated credential trusts
`https://cognito-identity.amazonaws.com`. `AZURE_CLIENT_ID` doubles as the Cognito developer user
identifier, which keeps the `IdentityId` — the federated credential's subject — stable.

The token is fetched through a callable that runs on every credential refresh, never cached: a
Cognito token is valid for 15 minutes by default while the Entra token lasts about an hour, so an
assertion minted once at cold start would be stale by the first refresh on a warm container.

With neither flow configured, `DefaultAzureCredential` falls through to its remaining credential
types, and none of them authenticate inside a Lambda — the failure surfaces at token acquisition on
the first upload, not when the client is built.

Setting neither `DCE_ENDPOINT` nor `DCR_CONFIG` leaves a Lambda on v1, behaving exactly as before.
The Azure SDK is imported inside the v2 path, not at module scope, so the layer still loads and
forwards on v1 in a package set that has no `azure-*` installed.