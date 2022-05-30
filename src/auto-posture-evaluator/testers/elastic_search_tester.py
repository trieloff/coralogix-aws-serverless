import time
import boto3
import interfaces
import json


def _format_string_to_json(text):
    return json.loads(text)


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_elastic_search_client = boto3.client('es')
        self.cache = {}
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.elastic_search_domain_names = self.aws_elastic_search_client.list_domain_names()

    def declare_tested_service(self) -> str:
        return 'elastic_search'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        return self.detect_elastic_search_cluster_using_vpc() + \
               self.detect_elastic_search_cluster_encryption_enabled() + \
               self.detect_elastic_search_cluster_using_kms_cmk() + \
               self.detect_elastic_search_cluster_using_latest_engine_version() + \
               self.detect_elastic_search_domain_not_publicly_accessible() + \
               self.detect_elastic_search_service_encryption_at_rest_disabled() + \
               self.detect_elastic_search_node_to_node_encryption_disabled() + \
               self.detect_elastic_search_dedicated_master_enabled()

    def _append_elastic_search_test_result(self, elastic_search, test_name, issue_status):
        return {
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": elastic_search['DomainName'],
            "item_type": "elastic_search_cluster",
            "test_name": test_name,
            "test_result": issue_status
        }

    def _check_es_domain_not_publicly_accessible(self, access_policy):
        access_policy = _format_string_to_json(access_policy)
        is_exposed = False
        for statement in access_policy['Statement']:
            if 'Effect' in statement and statement['Effect'] == 'Deny':
                continue
            if 'Principal' in statement and 'AWS' in statement['Principal'] and statement['Principal'][
                'AWS'] == '*' and 'Condition' not in statement:
                is_exposed = True
                break
            if 'IpAddress' in statement['Condition'] and 'aws:SourceIp' in statement['Condition'][
                'IpAddress'] and '0.0.0.0/0' in statement['Condition']['IpAddress']['aws:SourceIp']:
                is_exposed = True
                break
        return is_exposed

    def detect_elastic_search_cluster_using_latest_engine_version(self):
        test_name = "aws_elastic_search_cluster_using_latest_engine_version"
        result = []
        for elastic_search in self.elastic_search_domain_names['DomainNames']:
            domain_description = self.aws_elastic_search_client.describe_elasticsearch_domain(
                DomainName=elastic_search['DomainName'])
            try:
                if domain_description['DomainStatus']['ServiceSoftwareOptions']['CurrentVersion'] == \
                        domain_description['DomainStatus']['ServiceSoftwareOptions']['NewVersion'] or (
                        domain_description['DomainStatus']['ServiceSoftwareOptions']['NewVersion'] == '' and
                        domain_description['DomainStatus']['ServiceSoftwareOptions']['UpdateAvailable'] == False):
                    result.append(
                        self._append_elastic_search_test_result(elastic_search, test_name, "no_issue_found"))
                else:
                    result.append(self._append_elastic_search_test_result(elastic_search, test_name, "issue_found"))
            except KeyError as e:
                raise Exception("Elastic Search Using Latest Engine Version - Key error: ", e)
        return result

    def detect_elastic_search_cluster_using_vpc(self):
        test_name = "aws_elastic_search_cluster_using_vpc"
        result = []
        for elastic_search in self.elastic_search_domain_names['DomainNames']:
            domain_description = self.aws_elastic_search_client.describe_elasticsearch_domain(
                DomainName=elastic_search['DomainName'])
            try:
                if 'VPCOptions' in domain_description['DomainStatus'] and \
                        domain_description['DomainStatus']['VPCOptions']['VPCId'] and len(
                    domain_description['DomainStatus']['VPCOptions']['SubnetIds']):
                    result.append(self._append_elastic_search_test_result(elastic_search, test_name, "no_issue_found"))
                else:
                    result.append(self._append_elastic_search_test_result(elastic_search, test_name, "issue_found"))
            except KeyError as e:
                raise Exception("Elastic Search Using Vpc - Key error", e)
        return result

    def detect_elastic_search_cluster_encryption_enabled(self):
        test_name = "aws_elastic_search_cluster_encryption_enabled"
        result = []
        for elastic_search in self.elastic_search_domain_names['DomainNames']:
            domain_description = self.aws_elastic_search_client.describe_elasticsearch_domain(
                DomainName=elastic_search['DomainName'])
            try:
                if domain_description['DomainStatus']['EncryptionAtRestOptions']['Enabled']:
                    result.append(self._append_elastic_search_test_result(elastic_search, test_name, "no_issue_found"))
                else:
                    result.append(self._append_elastic_search_test_result(elastic_search, test_name, "issue_found"))
            except KeyError:
                raise Exception("Elastic Search Encryption Enabled - Key error")
        return result

    def detect_elastic_search_cluster_using_kms_cmk(self):
        test_name = "aws_elastic_search_cluster_using_kms_cmk"
        result = []
        for elastic_search in self.elastic_search_domain_names['DomainNames']:
            domain_description = self.aws_elastic_search_client.describe_elasticsearch_domain(
                DomainName=elastic_search['DomainName'])
            try:
                if domain_description['DomainStatus']['EncryptionAtRestOptions']['Enabled'] == True and \
                        domain_description['DomainStatus']['EncryptionAtRestOptions'][
                            'KmsKeyId'] != '(Default) aws/es':
                    result.append(self._append_elastic_search_test_result(elastic_search, test_name, "no_issue_found"))
                else:
                    result.append(self._append_elastic_search_test_result(elastic_search, test_name, "issue_found"))
            except KeyError:
                raise Exception("Elastic Search Using KMS CMK - Key error")
        return result

    def detect_elastic_search_domain_not_publicly_accessible(self):
        test_name = "aws_elastic_search_domain_not_publicly_accessible"
        result = []
        for elastic_search in self.elastic_search_domain_names['DomainNames']:
            domain_description = self.aws_elastic_search_client.describe_elasticsearch_domain(
                DomainName=elastic_search['DomainName'])
            if self._check_es_domain_not_publicly_accessible(domain_description['DomainStatus']['AccessPolicies']):
                result.append(self._append_elastic_search_test_result(elastic_search, test_name, "issue_found"))
            else:
                result.append(self._append_elastic_search_test_result(elastic_search, test_name, "no_issue_found"))
        return result

    def detect_elastic_search_service_encryption_at_rest_disabled(self):
        test_name = "aws_elastic_search_service_encryption_at_rest_disabled"
        result = []
        for elastic_search in self.elastic_search_domain_names['DomainNames']:
            domain_description = self.aws_elastic_search_client.describe_elasticsearch_domain(
                DomainName=elastic_search['DomainName'])
            if 'DomainStatus' in domain_description and 'EncryptionAtRestOptions' in domain_description[
                'DomainStatus'] and \
                    domain_description['DomainStatus']['EncryptionAtRestOptions']['Enabled']:
                result.append(self._append_elastic_search_test_result(elastic_search, test_name, "no_issue_found"))
            else:
                result.append(self._append_elastic_search_test_result(elastic_search, test_name, "issue_found"))
        return result

    def detect_elastic_search_node_to_node_encryption_disabled(self):
        test_name = "aws_elastic_search_node_to_node_encryption_disabled"
        result = []
        for elastic_search in self.elastic_search_domain_names['DomainNames']:
            domain_description = self.aws_elastic_search_client.describe_elasticsearch_domain(
                DomainName=elastic_search['DomainName'])
            if 'DomainStatus' in domain_description and 'NodeToNodeEncryptionOptions' in domain_description[
                'DomainStatus'] and domain_description['DomainStatus'][
                'NodeToNodeEncryptionOptions']:
                result.append(self._append_elastic_search_test_result(elastic_search, test_name, "no_issue_found"))
            else:
                result.append(self._append_elastic_search_test_result(elastic_search, test_name, "issue_found"))
        return result

    def detect_elastic_search_dedicated_master_enabled(self):
        test_name = "aws_elastic_search_dedicated_master_enabled"
        result = []
        for elastic_search in self.elastic_search_domain_names['DomainNames']:
            domain_description = self.aws_elastic_search_client.describe_elasticsearch_domain(
                DomainName=elastic_search['DomainName'])
            if 'DomainStatus' in domain_description and 'ElasticsearchClusterConfig' in domain_description[
                'DomainStatus'] and domain_description['DomainStatus'][
                'ElasticsearchClusterConfig']['DedicatedMasterEnabled']:
                result.append(self._append_elastic_search_test_result(elastic_search, test_name, "no_issue_found"))
            else:
                result.append(self._append_elastic_search_test_result(elastic_search, test_name, "issue_found"))
        return result

