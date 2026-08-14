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