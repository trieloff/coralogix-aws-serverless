import json
import time
from unittest import result
import boto3
import botocore.exceptions
import interfaces
import requests
import urllib.parse


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_s3_client = boto3.client('s3')
        self.aws_s3_resource = boto3.resource('s3')
        self.aws_s3_control_client = boto3.client('s3control')
        self.aws_kms_client = boto3.client('kms')
        self.cache = {}
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.s3_buckets = boto3.client('s3').list_buckets()

    def declare_tested_service(self) -> str:
        return 's3'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        return \
            self.detect_write_enabled_buckets(self.s3_buckets) + \
            self.detect_publicly_accessible_s3_buckets_by_acl(self.s3_buckets) + \
            self.detect_non_versioned_s3_buckets(self.s3_buckets) + \
            self.detect_not_encrypted_s3_buckets(self.s3_buckets) + \
            self.detect_full_control_allowed_s3_buckets(self.s3_buckets) + \
            self.detect_buckets_without_mfa_delete_s3_buckets(self.s3_buckets) + \
            self.detect_buckets_without_block_public_access_set(self.s3_buckets) + \
            self.detect_publicly_accessible_s3_buckets_by_policy(self.s3_buckets) + \
            self.detect_bucket_content_listable_by_users(self.s3_buckets) + \
            self.detect_bucket_content_permissions_viewable_by_users(self.s3_buckets) + \
            self.detect_bucket_content_permissions_modifiable_by_users(self.s3_buckets) + \
            self.detect_bucket_content_writable_by_anonymous(self.s3_buckets) + \
            self.detect_buckets_without_logging_set(self.s3_buckets) + \
            self.detect_buckets_accessible_by_http_url(self.s3_buckets) + \
            self.detect_buckets_accessible_by_https_url(self.s3_buckets) + \
            self.detect_bucket_logging_disabled(self.s3_buckets) + \
            self.detect_bucket_not_encrypted_with_cmk(self.s3_buckets) + \
            self.detect_block_public_access_setting_disabled() + \
            self.detect_bucket_not_configured_with_block_public_access(self.s3_buckets) + \
            self.detect_buckets_with_global_upload_and_delete_permission(self.s3_buckets) + \
            self.detect_bucket_has_global_list_acl_permission_through_acl(self.s3_buckets) + \
            self.detect_bucket_has_global_put_permissions_enabled_via_bucket_policy(self.s3_buckets) + \
            self.detect_bucket_has_global_list_permissions_enabled_via_bucket_policy(self.s3_buckets) + \
            self.detect_bucket_has_global_get_permissions_enabled_via_bucket_policy(self.s3_buckets)

    def detect_write_enabled_buckets(self, buckets_list):
        return self._detect_buckets_with_permissions_matching(buckets_list, "WRITE", "write_enabled_s3_buckets")

    def detect_publicly_accessible_s3_buckets_by_acl(self, buckets_list):
        test_name = "publicly_accessible_s3_buckets_by_acl"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket_meta["Name"]
            cur_bucket_permissions = self._get_bucket_acl(bucket_name)
            for grantee in cur_bucket_permissions.grants:
                if grantee["Grantee"]["Type"] == "Group" and (
                        grantee["Grantee"]["URI"] == "http://acs.amazonaws.com/groups/global/AllUsers" or
                        grantee["Grantee"]["URI"] == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"):
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "item_type": "s3_bucket",
                        "test_name": test_name,
                        "permissions": cur_bucket_permissions.grants,
                        "test_result": "issue_found"
                    })
                    issue_detected = True
            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})

        return result

    def detect_non_versioned_s3_buckets(self, buckets_list):
        test_name = "non_versioned_s3_buckets"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            cur_bucket_versioning = self._get_bucket_versioning(bucket_name)
            if not cur_bucket_versioning.status:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "issue_found"
                })
            else:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})

        return result

    def detect_not_encrypted_s3_buckets(self, buckets_list):
        test_name = "not_encrypted_s3_buckets"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket_meta["Name"]
            try:
                self.aws_s3_client.get_bucket_encryption(Bucket=bucket_name)
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "item_type": "s3_bucket",
                        "test_name": test_name,
                        "test_result": "issue_found"
                    })
                    issue_detected = True
                else:
                    raise ex

            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})

        return result

    def detect_full_control_allowed_s3_buckets(self, buckets_list):
        return self._detect_buckets_with_permissions_matching(buckets_list, "FULL_CONTROL", "full_control_allowed_s3_buckets")

    def detect_buckets_without_mfa_delete_s3_buckets(self, buckets_list):
        test_name = "no_delete_mfa_s3_buckets"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            cur_bucket_versioning = self._get_bucket_versioning(bucket_name)
            if not cur_bucket_versioning.mfa_delete:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "issue_found"
                })
            else:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})

        return result

    def detect_buckets_without_block_public_access_set(self, buckets_list):
        test_name = "no_block_public_access_set"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket_meta["Name"]
            try:
                public_access_block_kill_switch = self.aws_s3_client.get_public_access_block(Bucket=bucket_name)
                if not public_access_block_kill_switch["PublicAccessBlockConfiguration"]["BlockPublicAcls"] or \
                    not public_access_block_kill_switch["PublicAccessBlockConfiguration"]["IgnorePublicAcls"] or \
                    not public_access_block_kill_switch["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] or \
                    not public_access_block_kill_switch["PublicAccessBlockConfiguration"]["RestrictPublicBuckets"]:
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "item_type": "s3_bucket",
                        "test_name": test_name,
                        "public_access_block": public_access_block_kill_switch["PublicAccessBlockConfiguration"],
                        "test_result": "issue_found"
                    })
                    issue_detected = True
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "item_type": "s3_bucket",
                        "test_name": test_name,
                        "public_access_block": {},
                        "test_result": "issue_found"
                    })
                    issue_detected = True
                else:
                    raise ex

            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})

        return result

    def detect_publicly_accessible_s3_buckets_by_policy(self, buckets_list):
        test_name = "publicly_accessible_s3_buckets_by_policy"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy_status = self.aws_s3_client.get_bucket_policy_status(Bucket=bucket_name)
                if bucket_policy_status["PolicyStatus"]["IsPublic"]:
                    bucket_policy = self._get_bucket_policy(bucket_name)["Policy"]
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "item_type": "s3_bucket",
                        "test_name": test_name,
                        "policy": bucket_policy,
                        "test_result": "issue_found"
                    })
                    issue_detected = True
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket is not publicly accessible by policy
                    pass
                else:
                    raise ex

            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})

        return result

    def detect_bucket_content_listable_by_users(self, buckets_list):
        test_name = "s3_bucket_content_listable_by_users"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy = self._get_bucket_policy(bucket_name)
                policy_statements = json.loads(bucket_policy['Policy'])['Statement']
                for statement in policy_statements:
                    if str(statement["Resource"]).endswith('*'):
                        result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "item_type": "s3_bucket",
                            "test_name": test_name,
                            "policy": bucket_policy,
                            "test_result": "issue_found"
                        })
                        issue_detected = True
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket content is not listable by policy
                    pass
                else:
                    raise ex

            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})

        return result

    def detect_bucket_content_permissions_viewable_by_users(self, buckets_list):
        test_name = "s3_bucket_content_permissions_viewable_by_users"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy = self._get_bucket_policy(bucket_name)
                policy_statements = json.loads(bucket_policy['Policy'])['Statement']
                for statement in policy_statements:
                    if statement["Principal"] == '*' and "s3:GetObjectAcl" in statement["Action"] and str(statement["Resource"]).endswith('*'):
                        result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "item_type": "s3_bucket",
                            "test_name": test_name,
                            "policy": bucket_policy,
                            "test_result": "issue_found"
                        })
                        issue_detected = True
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket content is not listable by policy
                    pass
                else:
                    raise ex

            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})

        return result

    def detect_bucket_content_permissions_modifiable_by_users(self, buckets_list):
        test_name = "s3_bucket_content_permissions_modifiable_by_users"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy = self._get_bucket_policy(bucket_name)
                policy_statements = json.loads(bucket_policy['Policy'])['Statement']
                for statement in policy_statements:
                    if statement["Principal"] == '*' and "s3:PutObjectAcl" in statement["Action"] and str(statement["Resource"]).endswith('*'):
                        result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "item_type": "s3_bucket",
                            "test_name": test_name,
                            "policy": bucket_policy,
                            "test_result": "issue_found"
                        })
                        issue_detected = True
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket content is not listable by policy
                    pass
                else:
                    raise ex

            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})

        return result

    def detect_bucket_content_writable_by_anonymous(self, buckets_list):
        test_name = "s3_bucket_content_writable_by_anonymous"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy = self._get_bucket_policy(bucket_name)
                policy_statements = json.loads(bucket_policy['Policy'])['Statement']
                for statement in policy_statements:
                    if statement["Principal"] == '*' and "s3:PutObject" in statement["Action"] and str(statement["Resource"]).endswith('*'):
                        result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "item_type": "s3_bucket",
                            "test_name": test_name,
                            "policy": bucket_policy,
                            "test_result": "issue_found"
                        })
                        issue_detected = True
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket content is not listable by policy
                    pass
                else:
                    raise ex

            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})

        return result

    def detect_buckets_without_logging_set(self, buckets_list):
        test_name = "no_logging_policy_set"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket_meta["Name"]
            try:
                raw_logging_policy = self.aws_s3_resource.BucketLogging(bucket_name)
                if not raw_logging_policy.logging_enabled:
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "item_type": "s3_bucket",
                        "test_name": test_name,
                        "test_result": "issue_found"
                    })
                    issue_detected = True
            except botocore.exceptions.ClientError as ex:
                raise ex

            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})

        return result

    def detect_buckets_accessible_by_http_url(self, buckets_list):
        test_name = "publicly_accessible_s3_buckets_by_http_url"
        protocol = "http"
        result = self._test_bucket_url_access(buckets_list, protocol, test_name)

        return result

    def detect_buckets_accessible_by_https_url(self, buckets_list):
        test_name = "publicly_accessible_s3_buckets_by_https_url"
        protocol = "https"
        result = self._test_bucket_url_access(buckets_list, protocol, test_name)

        return result

    def detect_bucket_logging_disabled(self, buckets_list):
        test_name = "bucket_logging_disabled"
        result = []
        for bucket in buckets_list["Buckets"]:
            bucket_name = bucket["Name"]
            logging = self.aws_s3_client.get_bucket_logging(Bucket=bucket_name)
            if not logging.get("LoggingEnabled"):
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "issue_found"
                })
            else:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"
                })
        return result

    def detect_bucket_not_encrypted_with_cmk(self, buckets_list):
        test_name = "bucket_not_encrypted_with_cmk"
        result = []
        for bucket in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket["Name"]
            try:
                encryption = self.aws_s3_client.get_bucket_encryption(Bucket=bucket_name)
                for rule in encryption['ServerSideEncryptionConfiguration']['Rules']:
                    if not rule['BucketKeyEnabled']: continue
                    sse_algorithm = rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
                    if sse_algorithm == 'AES256':
                        issue_detected = True
                        break
                    else:
                        if not rule['ApplyServerSideEncryptionByDefault'].get('KMSMasterKeyID'):
                            issue_detected = True
                            break
                        key_id = rule['ApplyServerSideEncryptionByDefault']['KMSMasterKeyID']
                        try:
                            kms_response = self.aws_kms_client.list_aliases(KeyId=key_id)
                        except:
                            issue_detected = True
                            break
                        for alias in kms_response['Aliases']:
                            if alias['AliasName'] == 'alias/aws/s3':
                                issue_detected = True
                                break
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    issue_detected = True
                else:
                    raise ex

            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"
                })
            else:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "issue_found"
                })

        return result
    
    def detect_block_public_access_setting_disabled(self):
        test_name = "block_public_access_setting_disabled"
        result = []
        issue_detected = False
        try:
            public_access_setting = self.aws_s3_control_client.get_public_access_block(AccountId=self.account_id)
            conf = public_access_setting["PublicAccessBlockConfiguration"]
            if not conf["BlockPublicAcls"] and not conf["IgnorePublicAcls"] and not conf["BlockPublicPolicy"] and not conf["RestrictPublicBuckets"]:
                issue_detected = True
        except botocore.exceptions.ClientError as ex:
            if ex.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                issue_detected = True
            else:
                raise ex
        if issue_detected:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": self.account_id,
                "item_type": "s3_account",
                "test_name": test_name,
                "test_result": "issue_found"
            })
        else:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": self.account_id,
                "item_type": "s3_account",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
        return result

    def detect_bucket_not_configured_with_block_public_access(self, buckets_list):
        test_name = "bucket_not_configured_with_block_public_access"
        result = []
        for bucket in buckets_list["Buckets"]:
            bucket_name = bucket["Name"]
            issue_detected = False
            try:
                public_access = self.aws_s3_client.get_public_access_block(Bucket=bucket_name)
                conf = public_access["PublicAccessBlockConfiguration"]
                if not conf["BlockPublicAcls"] and not conf["IgnorePublicAcls"] and not conf["BlockPublicPolicy"] and not conf["RestrictPublicBuckets"]:
                    issue_detected = True
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    issue_detected = True
                else:
                    raise ex
            if issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "issue_found"
                })
            else:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"
                })
        return result

    def detect_buckets_with_global_upload_and_delete_permission(self, buckets_list):
        test_name = "buckets_with_global_upload_and_delete_permission"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            bucket_acl = self.aws_s3_client.get_bucket_acl(Bucket=bucket_name)
            issue_found = False
            for grant in bucket_acl["Grants"]:
                if (grant["Permission"] == "WRITE" or grant["Permission"] == "READ") and grant["Grantee"].get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "item_type": "s3_bucket",
                        "test_name": test_name,
                        "test_result": "issue_found"
                    })
                    issue_found = True
                    break
            if not issue_found:
                result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "item_type": "s3_bucket",
                        "test_name": test_name,
                        "test_result": "no_issue_found"
                })
        return result
             
    def detect_bucket_has_global_list_acl_permission_through_acl(self, buckets_list):
        test_name = "bucket_has_global_list_acl_permission_through_acl"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            bucket_acl = self.aws_s3_client.get_bucket_acl(Bucket=bucket_name)
            issue_found = False
            for grant in bucket_acl["Grants"]:
                if (grant["Permission"] == "WRITE_ACP" or grant["Permission"] == "READ_ACP") and grant["Grantee"].get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "item_type": "s3_bucket",
                        "test_name": test_name,
                        "test_result": "issue_found"
                    })
                    issue_found = True
                    break
            if not issue_found:
                result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "item_type": "s3_bucket",
                        "test_name": test_name,
                        "test_result": "no_issue_found"
                })
        return result
    
    def detect_bucket_has_global_list_permissions_enabled_via_bucket_policy(self, buckets_list):
        result = []
        test_name = "bucket_has_global_list_permissions_enabled_via_bucket_policy"
        for bucket_meta in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy = self._get_bucket_policy(bucket_name)
                policy_statements = json.loads(bucket_policy['Policy'])['Statement']
                for statement in policy_statements:
                    if statement["Effect"] == "Allow" and (statement["Principal"] == '*' or statement["Principal"] == {"AWS": "*"}) and (any([("List" in action or action=="s3:*") for action in statement["Action"]]) or "List" in statement["Action"] or statement["Action"]=="s3:*"):
                        result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "item_type": "s3_bucket",
                            "test_name": test_name,
                            "policy": bucket_policy,
                            "test_result": "issue_found"
                        })
                        issue_detected = True
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket content is not listable by policy
                    pass
                else:
                    raise ex

            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})
        return result

    def detect_bucket_has_global_get_permissions_enabled_via_bucket_policy(self, buckets_list):
        result = []
        test_name = "bucket_has_global_get_permissions_enabled_via_bucket_policy"
        for bucket_meta in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy = self._get_bucket_policy(bucket_name)
                policy_statements = json.loads(bucket_policy['Policy'])['Statement']
                for statement in policy_statements:
                    if statement["Effect"] == "Allow" and (statement["Principal"] == '*' or statement["Principal"] == {"AWS": "*"}) and (any([("Get" in action or action=="s3:*") for action in statement["Action"]]) or "Get" in statement["Action"] or statement["Action"]=="s3:*"):
                        result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "item_type": "s3_bucket",
                            "test_name": test_name,
                            "policy": bucket_policy,
                            "test_result": "issue_found"
                        })
                        issue_detected = True
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket content is not listable by policy
                    pass
                else:
                    raise ex

            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})
        return result

    def detect_bucket_has_global_put_permissions_enabled_via_bucket_policy(self, buckets_list):
        result = []
        test_name = "bucket_has_global_put_permissions_enabled_via_bucket_policy"
        for bucket_meta in buckets_list["Buckets"]:
            issue_detected = False
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy = self._get_bucket_policy(bucket_name)
                policy_statements = json.loads(bucket_policy['Policy'])['Statement']
                for statement in policy_statements:
                    if statement["Effect"] == "Allow" and (statement["Principal"] == '*' or statement["Principal"] == {"AWS": "*"}) and (any([("Put" in action or action=="s3:*") for action in statement["Action"]]) or "Put" in statement["Action"] or statement["Action"]=="s3:*"):
                        result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "item_type": "s3_bucket",
                            "test_name": test_name,
                            "policy": bucket_policy,
                            "test_result": "issue_found"
                        })
                        issue_detected = True
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket content is not listable by policy
                    pass
                else:
                    raise ex

            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})
        return result

    def _test_bucket_url_access(self, buckets_list, protocol, test_name):
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            issue_detected = False
            try:
                url = protocol + "://" + urllib.parse.quote_plus(bucket_name) + ".s3.amazonaws.com"
                resp = requests.head(url)
                if resp.status_code >= 200 and resp.status_code < 300:
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "item_type": "s3_bucket",
                        "test_name": test_name,
                        "bucket_url": url,
                        "test_result": "issue_found"
                    })
                    issue_detected = True
            except:
                continue
            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"})
        return result

    def _get_bucket_policy(self, bucket_name):
        if "bucket_policy" not in self.cache:
            self.cache["bucket_policy"] = {}
        if bucket_name not in self.cache["bucket_policy"]:
            self.cache["bucket_policy"][bucket_name] = self.aws_s3_client.get_bucket_policy(Bucket=bucket_name)

        return self.cache["bucket_policy"][bucket_name]

    def _get_bucket_versioning(self, bucket_name):
        if "bucket_versioning" not in self.cache:
            self.cache["bucket_versioning"] = {}
        if bucket_name not in self.cache["bucket_versioning"]:
            self.cache["bucket_versioning"][bucket_name] = self.aws_s3_resource.BucketVersioning(bucket_name)
        return self.cache["bucket_versioning"][bucket_name]

    def _get_bucket_acl(self, bucket_name):
        if "bucket_acl" not in self.cache:
            self.cache["bucket_acl"] = {}
        if bucket_name not in self.cache["bucket_acl"]:
            self.cache["bucket_acl"][bucket_name] = self.aws_s3_resource.BucketAcl(bucket_name)
        return self.cache["bucket_acl"][bucket_name]

    def _detect_buckets_with_permissions_matching(self, buckets_list, permission_to_check, test_name):
        result = []
        write_enabled_buckets = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            cur_bucket_permissions = self._get_bucket_acl(bucket_name)
            issue_detected = False
            for grantee in cur_bucket_permissions.grants:
                if grantee["Permission"] == permission_to_check:
                    if bucket_name not in write_enabled_buckets:
                        write_enabled_buckets.append(bucket_name)
                        result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "item_type": "s3_bucket",
                            "test_name": test_name,
                            "permissions": cur_bucket_permissions.grants,
                            "test_result": "issue_found"
                        })
                        issue_detected = True
            if not issue_detected:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "item_type": "s3_bucket",
                    "test_name": test_name,
                    "test_result": "no_issue_found"
                })
        return result