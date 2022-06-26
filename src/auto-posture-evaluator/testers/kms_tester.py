import interfaces
import boto3
import time
import botocore.exceptions
from concurrent.futures import ThreadPoolExecutor


class Tester(interfaces.TesterInterface):
    def __init__(self, region_name) -> None:
        self.aws_kms_client = boto3.client('kms', region_name=region_name)
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.kms_keys = []
        self.ssm = boto3.client('ssm')
        self.region_name = region_name

    def declare_tested_provider(self) -> str:
        return 'aws'

    def declare_tested_service(self) -> str:
        return 'kms'

    def run_tests(self) -> list:
        if self.region_name == 'global' or self.region_name not in self._get_regions():
            return None
        self.kms_keys = self._get_kms_keys()

        executor_list = []
        return_values = []

        with ThreadPoolExecutor() as executor:
            executor_list.append(executor.submit(self.get_rotation_for_cmks_is_enabled, self.kms_keys))
            executor_list.append(executor.submit(self.get_kms_cmk_pending_deletion, self.kms_keys))

            for future in executor_list:
                return_values.extend(future.result())

        return return_values

    def _get_result_object(self, item, item_type, test_name, issue_status):
        return {
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": item,
            "item_type": item_type,
            "test_name": test_name,
            "test_result": issue_status
        }

    def _get_regions(self) -> list:
        region_list = []
        for page in self.ssm.get_paginator('get_parameters_by_path').paginate(
                Path='/aws/service/global-infrastructure/regions'
        ):
            for p in page['Parameters']:
                region_list.append(p['Value'])
        return region_list

    def _get_kms_keys(self):
        keys = []
        can_paginate = self.aws_kms_client.can_paginate('list_keys')
        if can_paginate:
            paginator = self.aws_kms_client.get_paginator('list_keys')
            response_iterator = paginator.paginate(PaginationConfig={'PageSize': 50})

            for page in response_iterator:
                keys.extend(page['Keys'])
        else:
            response = self.aws_kms_client.list_keys()
            keys.extend(response['Keys'])

        for key in keys:
            key_id = key['KeyId']
            response = self.aws_kms_client.describe_key(KeyId=key_id)
            key_manager = response['KeyMetadata']['KeyManager']
            key['key_manager'] = key_manager

        final_keys = list(filter(lambda x: x['key_manager'] == 'CUSTOMER', keys))
        return final_keys

    def get_rotation_for_cmks_is_enabled(self, keys):
        result = []
        test_name = "aws_kms_rotation_for_cmks_is_enabled"

        try:
            for key in keys:
                key_id = key['KeyId']
                response = self.aws_kms_client.get_key_rotation_status(KeyId=key_id)
                rotation_status = response['KeyRotationEnabled']
                if rotation_status:
                    result.append(self._get_result_object(key_id, "kms_policy", test_name, "no_issue_found"))
                else:
                    result.append(self._get_result_object(key_id, "kms_policy", test_name, "issue_found"))
            return result
        except botocore.exceptions.ClientError as ex:
            raise ex

    def get_kms_cmk_pending_deletion(self, keys):
        result = []
        test_name = "aws_kms_cmk_pending_deletion"

        try:
            for key in keys:
                key_id = key['KeyId']
                response = self.aws_kms_client.describe_key(KeyId=key_id)
                rotation_status = response['KeyMetadata']['KeyState']
                if rotation_status == 'PendingDeletion':
                    result.append(self._get_result_object(key_id, "kms_policy", test_name, "issue_found"))
                else:
                    result.append(self._get_result_object(key_id, "kms_policy", test_name, "no_issue_found"))
            return result
        except botocore.exceptions.ClientError as ex:
            raise ex
