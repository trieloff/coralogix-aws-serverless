import time
import boto3
import interfaces


def _return_default_port_on_redshift_engines():
    return 5439


def _return_default_custom_master_username_on_redshift_engines():
    return 'awsuser'


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_redshift_client = boto3.client('redshift')
        self.cache = {}
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.redshift_clusters = self.aws_redshift_client.describe_clusters()

    def declare_tested_service(self) -> str:
        return 'redshift'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        return self.detect_redshift_cluster_encrypted() + \
               self.detect_redshift_cluster_not_publicly_accessible() + \
               self.detect_redshift_cluster_not_using_default_port() + \
               self.detect_redshift_cluster_not_using_custom_master_username() + \
               self.detect_redshift_cluster_using_logging() + \
               self.detect_redshift_cluster_allow_version_upgrade() + \
               self.detect_redshift_cluster_requires_ssl() + \
               self.detect_redshift_cluster_not_using_ec2_classic()

    def _append_redshift_test_result(self, redshift, test_name, issue_status):
        return {
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": redshift['ClusterIdentifier'],
            "item_type": "redshift_cluster",
            "test_name": test_name,
            "test_result": issue_status
        }

    def _return_redshift_logging_status(self, cluster_identifier):
        return self.aws_redshift_client.describe_logging_status(ClusterIdentifier=cluster_identifier)

    def _return_parameter_group_names(self, parameter_groups):
        result = []
        for pg in parameter_groups:
            result.append(pg['ParameterGroupName'])
        return result

    def _return_cluster_parameter_data(self, group_name):
        return self.aws_redshift_client.describe_cluster_parameters(ParameterGroupName=group_name)

    def _return_ssl_enabled_on_parameter_groups(self, params):
        ssl_enabled = False
        for pg in params:
            if pg['ParameterName'].lower() == 'require_ssl' and pg['ParameterValue'].lower() == 'true':
                ssl_enabled = True
                break
        return ssl_enabled

    def detect_redshift_cluster_encrypted(self):
        test_name = "aws_redshift_encrypted_redshift_cluster"
        result = []
        for redshift in self.redshift_clusters['Clusters']:
            if not redshift['Encrypted']:
                result.append(self._append_redshift_test_result(redshift, test_name, "issue_found"))
            else:
                result.append(self._append_redshift_test_result(redshift, test_name, "no_issue_found"))
        return result

    def detect_redshift_cluster_not_publicly_accessible(self):
        test_name = "aws_redshift_not_publicly_accessible_redshift_cluster"
        result = []
        for redshift in self.redshift_clusters['Clusters']:
            if redshift['PubliclyAccessible']:
                result.append(self._append_redshift_test_result(redshift, test_name, "issue_found"))
            else:
                result.append(self._append_redshift_test_result(redshift, test_name, "no_issue_found"))
        return result

    def detect_redshift_cluster_not_using_default_port(self):
        test_name = "aws_redshift_cluster_not_using_default_port"
        result = []
        for redshift in self.redshift_clusters['Clusters']:
            if _return_default_port_on_redshift_engines() == redshift['Endpoint']['Port']:
                result.append(self._append_redshift_test_result(redshift, test_name, "issue_found"))
            else:
                result.append(self._append_redshift_test_result(redshift, test_name, "no_issue_found"))
        return result

    def detect_redshift_cluster_not_using_custom_master_username(self):
        test_name = "aws_redshift_cluster_not_using_custom_master_username"
        result = []
        for redshift in self.redshift_clusters['Clusters']:
            if _return_default_custom_master_username_on_redshift_engines() == redshift['MasterUsername'].lower():
                result.append(self._append_redshift_test_result(redshift, test_name, "issue_found"))
            else:
                result.append(self._append_redshift_test_result(redshift, test_name, "no_issue_found"))
        return result

    def detect_redshift_cluster_using_logging(self):
        test_name = "aws_redshift_cluster_using_logging"
        result = []
        for redshift in self.redshift_clusters['Clusters']:
            logging_metadata = self._return_redshift_logging_status(redshift['ClusterIdentifier'])
            if not logging_metadata['LoggingEnabled']:
                result.append(self._append_redshift_test_result(redshift, test_name, "issue_found"))
            else:
                result.append(self._append_redshift_test_result(redshift, test_name, "no_issue_found"))
        return result

    def detect_redshift_cluster_allow_version_upgrade(self):
        test_name = "aws_redshift_cluster_allow_version_upgrade"
        result = []
        for redshift in self.redshift_clusters['Clusters']:
            if not redshift['AllowVersionUpgrade']:
                result.append(self._append_redshift_test_result(redshift, test_name, "issue_found"))
            else:
                result.append(self._append_redshift_test_result(redshift, test_name, "no_issue_found"))
        return result

    def detect_redshift_cluster_requires_ssl(self):
        test_name = "aws_redshift_cluster_requires_ssl"
        result = []
        for redshift in self.redshift_clusters['Clusters']:
            issue_found = True
            for parameter_group_name in self._return_parameter_group_names(redshift['ClusterParameterGroups']):
                param_key_value = self._return_cluster_parameter_data(parameter_group_name)
                if 'Parameters' in param_key_value and len(param_key_value['Parameters']):
                    if self._return_ssl_enabled_on_parameter_groups(param_key_value['Parameters']):
                        issue_found = False
            if not issue_found:
                result.append(self._append_redshift_test_result(redshift, test_name, "no_issue_found"))
            else:
                result.append(self._append_redshift_test_result(redshift, test_name, "issue_found"))
        return result

    def detect_redshift_cluster_not_using_ec2_classic(self):
        test_name = "aws_redshift_cluster_not_using_ec2_classic"
        result = []
        for redshift in self.redshift_clusters['Clusters']:
            if not ('VpcId' in redshift and redshift['VpcId']):
                result.append(self._append_redshift_test_result(redshift, test_name, "issue_found"))
            else:
                result.append(self._append_redshift_test_result(redshift, test_name, "no_issue_found"))
        return result

