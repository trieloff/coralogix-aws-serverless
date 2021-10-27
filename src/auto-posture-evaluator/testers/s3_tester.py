import json
import time
import boto3
import botocore.exceptions
import interfaces
import requests
import urllib.parse


class S3Tester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_s3_client = boto3.client('s3')
        self.aws_s3_resource = boto3.resource('s3')
        self.cache = {}

    def declare_tested_service(self) -> str:
        return 's3'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def declare_tested_resource_type(self) -> str:
        return 's3_bucket'

    def declare_required_args(self) -> list:
        return ["s3_buckets", "regions"]

    def run_tests(self, args_object) -> list:
        if "s3_buckets" not in args_object:
            raise Exception("No S3 buckets list was found in request.")
        if "regions" not in args_object:
            raise Exception("No AWS regions list was found in request.")
        return \
            self.detect_write_enabled_buckets(args_object["s3_buckets"]) + \
            self.detect_publicly_accessible_s3_buckets_by_acl(args_object["s3_buckets"]) + \
            self.detect_non_versioned_s3_buckets(args_object["s3_buckets"]) + \
            self.detect_not_encrypted_s3_buckets(args_object["s3_buckets"]) + \
            self.detect_full_control_allowed_s3_buckets(args_object["s3_buckets"]) + \
            self.detect_buckets_without_mfa_delete_s3_buckets(args_object["s3_buckets"]) + \
            self.detect_buckets_without_block_public_access_set(args_object["s3_buckets"]) + \
            self.detect_publicly_accessible_s3_buckets_by_policy(args_object["s3_buckets"]) + \
            self.detect_bucket_content_listable_by_users(args_object["s3_buckets"]) + \
            self.detect_bucket_content_permissions_viewable_by_users(args_object["s3_buckets"]) + \
            self.detect_bucket_content_permissions_modifiable_by_users(args_object["s3_buckets"]) + \
            self.detect_bucket_content_writable_by_anonymous(args_object["s3_buckets"]) + \
            self.detect_buckets_without_logging_set(args_object["s3_buckets"]) + \
            self.detect_buckets_accessible_by_http_url(args_object["s3_buckets"]) + \
            self.detect_buckets_accessible_by_https_url(args_object["s3_buckets"])

    def detect_write_enabled_buckets(self, buckets_list):
        return self._detect_buckets_with_permissions_matching(buckets_list, "WRITE", "write_enabled_s3_buckets")

    def detect_publicly_accessible_s3_buckets_by_acl(self, buckets_list):
        test_name = "publicly_accessible_s3_buckets_by_acl"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            cur_bucket_permissions = self._get_bucket_acl(bucket_name)
            for grantee in cur_bucket_permissions.grants:
                if grantee["Grantee"]["Type"] == "Group" and (
                        grantee["Grantee"]["URI"] == "http://acs.amazonaws.com/groups/global/AllUsers" or
                        grantee["Grantee"]["URI"] == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"):
                    result.append({
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "test_name": test_name,
                        "permissions": cur_bucket_permissions.grants
                    })

        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})

        return result

    def detect_non_versioned_s3_buckets(self, buckets_list):
        test_name = "non_versioned_s3_buckets"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            cur_bucket_versioning = self._get_bucket_versioning(bucket_name)
            if not cur_bucket_versioning.status:
                result.append({
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "test_name": test_name
                })

        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})

        return result

    def detect_not_encrypted_s3_buckets(self, buckets_list):
        test_name = "not_encrypted_s3_buckets"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            try:
                self.aws_s3_client.get_bucket_encryption(Bucket=bucket_name)
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    result.append({
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "test_name": test_name
                    })
                else:
                    raise ex

        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})

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
                    "timestamp": time.time(),
                    "item": bucket_name,
                    "test_name": test_name
                })

        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})

        return result

    def detect_buckets_without_block_public_access_set(self, buckets_list):
        test_name = "no_block_public_access_set"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            try:
                public_access_block_kill_switch = self.aws_s3_client.get_public_access_block(Bucket=bucket_name)
                if not public_access_block_kill_switch["PublicAccessBlockConfiguration"]["BlockPublicAcls"] or \
                    not public_access_block_kill_switch["PublicAccessBlockConfiguration"]["IgnorePublicAcls"] or \
                    not public_access_block_kill_switch["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] or \
                    not public_access_block_kill_switch["PublicAccessBlockConfiguration"]["RestrictPublicBuckets"]:
                    result.append({
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "test_name": test_name,
                        "public_access_block": public_access_block_kill_switch["PublicAccessBlockConfiguration"]
                    })
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    result.append({
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "test_name": test_name,
                        "public_access_block": {}
                    })
                else:
                    raise ex

        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})

        return result

    def detect_publicly_accessible_s3_buckets_by_policy(self, buckets_list):
        test_name = "publicly_accessible_s3_buckets_by_policy"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy_status = self.aws_s3_client.get_bucket_policy_status(Bucket=bucket_name)
                if bucket_policy_status["PolicyStatus"]["IsPublic"]:
                    bucket_policy = self._get_bucket_policy(bucket_name)["Policy"]
                    result.append({
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "test_name": test_name,
                        "policy": bucket_policy
                    })
            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket is not publicly accessible by policy
                    pass
                else:
                    raise ex

        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})

        return result

    def detect_bucket_content_listable_by_users(self, buckets_list):
        test_name = "s3_bucket_content_listable_by_users"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy = self._get_bucket_policy(bucket_name)
                policy_statements = json.loads(bucket_policy['Policy'])['Statement']
                for statement in policy_statements:
                    if str(statement["Resource"]).endswith('*'):
                        result.append({
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "test_name": test_name,
                            "policy": bucket_policy
                        })

            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket content is not listable by policy
                    pass
                else:
                    raise ex

        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})

        return result

    def detect_bucket_content_permissions_viewable_by_users(self, buckets_list):
        test_name = "s3_bucket_content_permissions_viewable_by_users"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy = self._get_bucket_policy(bucket_name)
                policy_statements = json.loads(bucket_policy['Policy'])['Statement']
                for statement in policy_statements:
                    if statement["Principal"] == '*' and "s3:GetObjectAcl" in statement["Action"] and str(statement["Resource"]).endswith('*'):
                        result.append({
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "test_name": test_name,
                            "policy": bucket_policy
                        })

            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket content is not listable by policy
                    pass
                else:
                    raise ex

        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})

        return result

    def detect_bucket_content_permissions_modifiable_by_users(self, buckets_list):
        test_name = "s3_bucket_content_permissions_modifiable_by_users"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy = self._get_bucket_policy(bucket_name)
                policy_statements = json.loads(bucket_policy['Policy'])['Statement']
                for statement in policy_statements:
                    if statement["Principal"] == '*' and "s3:PutObjectAcl" in statement["Action"] and str(statement["Resource"]).endswith('*'):
                        result.append({
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "test_name": test_name,
                            "policy": bucket_policy
                        })

            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket content is not listable by policy
                    pass
                else:
                    raise ex

        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})

        return result

    def detect_bucket_content_writable_by_anonymous(self, buckets_list):
        test_name = "s3_bucket_content_writable_by_anonymous"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            try:
                bucket_policy = self._get_bucket_policy(bucket_name)
                policy_statements = json.loads(bucket_policy['Policy'])['Statement']
                for statement in policy_statements:
                    if statement["Principal"] == '*' and "s3:PutObject" in statement["Action"] and str(statement["Resource"]).endswith('*'):
                        result.append({
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "test_name": test_name,
                            "policy": bucket_policy
                        })

            except botocore.exceptions.ClientError as ex:
                if ex.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    # No policy means the bucket content is not listable by policy
                    pass
                else:
                    raise ex

        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})

        return result

    def detect_buckets_without_logging_set(self, buckets_list):
        test_name = "no_logging_policy_set"
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            try:
                raw_logging_policy = self.aws_s3_resource.BucketLogging(bucket_name)
                if not raw_logging_policy.logging_enabled:
                    result.append({
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "test_name": test_name
                    })
            except botocore.exceptions.ClientError as ex:
                raise ex

        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})

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

    def _test_bucket_url_access(self, buckets_list, protocol, test_name):
        result = []
        for bucket_meta in buckets_list["Buckets"]:
            bucket_name = bucket_meta["Name"]
            try:
                url = protocol + "://" + urllib.parse.quote_plus(bucket_name) + ".s3.amazonaws.com"
                resp = requests.head(url)
                if resp.status_code >= 200 and resp.status_code < 300:
                    result.append({
                        "timestamp": time.time(),
                        "item": bucket_name,
                        "test_name": test_name,
                        "bucket_url": url
                    })
            except:
                continue
        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})
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
            for grantee in cur_bucket_permissions.grants:
                if grantee["Permission"] == permission_to_check:
                    if bucket_name not in write_enabled_buckets:
                        write_enabled_buckets.append(bucket_name)
                        result.append({
                            "timestamp": time.time(),
                            "item": bucket_name,
                            "test_name": test_name,
                            "permissions": cur_bucket_permissions.grants
                        })
        if len(result) == 0:
            result.append({
                "timestamp": time.time(),
                "item": None,
                "test_name": test_name})
        return result
