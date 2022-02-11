# AWS Sentinel connection layer

This repository contains the code for an AWS lambda layer that is used in a custom terraform module here - https://github.com/cds-snc/terraform-modules/tree/main/sentinel_forwarder
which forwards AWS logs to an Azure LogAnalytics Workspace and ultimately Microsoft Sentinel. Please see the module for a reference implementation.

The code can handle the following types of logs
- CloudTrail (.json.gz)
- Load balancer (.log.gz)
- VPC flow logs (.log.gz)
- WAF ACL (.gz)
- GuardDuty
- SecurityHub (via EventHub)
- Generic application json logs

You will need to add your Log Analytics Workspace Customer ID and Shared Key. AWS logs are automatically assigned a LogType.
Custom application logs are given the log type defined through the `var.log_type`. They also need to be nested inside a json
object with the key, `application_log`. ex: `{'application_log': {'foo': 'bar'}}` for the layer code to forward it to Azure Sentinel.