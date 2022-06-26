import time
import boto3
import interfaces
import concurrent.futures


class Tester(interfaces.TesterInterface):
    def __init__(self, region_name) -> None:
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.aws_neptune_client = boto3.client('neptune', region_name=region_name)
        self.db_clusters = self._get_all_neptune_clusters()
        self.ssm = boto3.client('ssm')
        self.region_name = region_name

    def declare_tested_provider(self) -> str:
        return "aws"

    def declare_tested_service(self) -> str:
        return "neptune"

    def run_tests(self) -> list:
        if self.region_name == 'global' or self.region_name not in self._get_regions():
            return None
        executor_list = []
        return_value = []
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor_list.append(executor.submit(self.get_database_encryption_disabled))
            executor_list.append(executor.submit(self.get_neptune_cluster_audit_logs_disabled))

            for future in executor_list:
                return_value += future.result()

        return return_value

    def _get_regions(self) -> list:
        region_list = []
        for page in self.ssm.get_paginator('get_parameters_by_path').paginate(
                Path='/aws/service/global-infrastructure/regions'
        ):
            for p in page['Parameters']:
                region_list.append(p['Value'])
        return region_list

    def _get_all_neptune_clusters(self):
        db_clusters = []

        paginator = self.aws_neptune_client.get_paginator('describe_db_clusters')
        response_iterator = paginator.paginate()

        for page in response_iterator:
            db_clusters.extend(page["DBClusters"])

        return db_clusters

    def _append_neptune_cluster_test_result(self, item, item_type, test_name, issue_status):
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

    def get_database_encryption_disabled(self):
        result = []
        test_name = "aws_neptune_database_encryption_disabled"

        db_clusters = self.db_clusters

        for instance in db_clusters:
            identifier = instance['DBClusterIdentifier']
            storage_encrypted = instance['StorageEncrypted']

            if storage_encrypted:
                result.append(self._append_neptune_cluster_test_result(identifier, "neptune_db_cluster", test_name, "no_issue_found"))
            else:
                result.append(self._append_neptune_cluster_test_result(identifier, "neptune_db_cluster", test_name, "issue_found"))

        return result

    def get_neptune_cluster_audit_logs_disabled(self):
        result = []
        test_name = "aws_neptune_cluster_audit_logs_disabled"

        db_clusters = self.db_clusters

        for instance in db_clusters:
            identifier = instance['DBClusterIdentifier']
            export_logs = instance.get('EnabledCloudwatchLogsExports')

            if export_logs is not None:
                if any([i.startswith("audit") for i in export_logs]):
                    result.append(self._append_neptune_cluster_test_result(identifier, "neptune_db_cluster", test_name, "no_issue_found"))
                else:
                    result.append(self._append_neptune_cluster_test_result(identifier, "neptune_db_cluster", test_name, "issue_found"))
            else:
                result.append(self._append_neptune_cluster_test_result(identifier, "neptune_db_cluster", test_name, "issue_found"))
        return result
