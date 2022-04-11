import time
import boto3
import interfaces


def _return_default_port_on_elasticache_engines(cluster_type):
    if cluster_type == 'redis':
        return 6379
    elif cluster_type == 'memcached':
        return 11211
    else:
        return None


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_elasticache_client = boto3.client('elasticache')
        self.cache = {}
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.elasticache_clusters = self.aws_elasticache_client.describe_cache_clusters(ShowCacheNodeInfo=True)

    def declare_tested_service(self) -> str:
        return 'elasticache'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        return self.detect_elasticache_cluster_not_using_default_port() + \
               self.detect_elasticache_cluster_using_vpc() + \
               self.detect_elasticache_cluster_using_latest_engine_version()

    def _append_elasticache_test_result(self, elasticache, test_name, issue_status):
        return {
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": elasticache['CacheClusterId'],
            "item_type": "elasticache_cluster",
            "test_name": test_name,
            "test_result": issue_status
        }

    def _return_latest_version_for_given_engine(self, engine_type):
        versions = self.aws_elasticache_client.describe_cache_engine_versions(
            DefaultOnly=False,
            Engine=engine_type,
            MaxRecords=100,
        )
        return versions['CacheEngineVersions'][-1]

    def _return_cluster_using_default_port(self, engine_type, elasticache):
        engine_default_port = _return_default_port_on_elasticache_engines(engine_type)
        for node in elasticache['CacheNodes']:
            if node['Endpoint']['Port'] == engine_default_port:
                return True
        return False

    def detect_elasticache_cluster_not_using_default_port(self):
        test_name = "elasticache_cluster_not_using_default_port"
        result = []
        for elasticache in self.elasticache_clusters['CacheClusters']:
            if self._return_cluster_using_default_port(elasticache['Engine'], elasticache):
                result.append(self._append_elasticache_test_result(elasticache, test_name, "issue_found"))
            else:
                result.append(self._append_elasticache_test_result(elasticache, test_name, "no_issue_found"))

        return result

    def detect_elasticache_cluster_using_vpc(self):
        test_name = "elasticache_cluster_using_vpc"
        result = []
        for elasticache in self.elasticache_clusters['CacheClusters']:
            if 'CacheSubnetGroupName' in elasticache and elasticache['CacheSubnetGroupName']:
                result.append(self._append_elasticache_test_result(elasticache, test_name, "no_issue_found"))
            else:
                result.append(self._append_elasticache_test_result(elasticache, test_name, "issue_found"))
        return result

    def detect_elasticache_cluster_using_latest_engine_version(self):
        test_name = "elasticache_cluster_using_latest_engine_version"
        result = []
        for elasticache in self.elasticache_clusters['CacheClusters']:
            if self._return_latest_version_for_given_engine(elasticache['Engine'])[
                        'CacheEngineVersionDescription'].split(
                        ' ')[-1] != elasticache[
                        'EngineVersion'] and self._return_latest_version_for_given_engine(elasticache['Engine'])[
                        'EngineVersion'] != elasticache[
                        'EngineVersion']:
                result.append(self._append_elasticache_test_result(elasticache, test_name, "issue_found"))
            else:
                result.append(self._append_elasticache_test_result(elasticache, test_name, "no_issue_found"))
        return result

