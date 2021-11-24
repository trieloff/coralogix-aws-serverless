import time
import boto3
import interfaces


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_cloudfront_client = boto3.client('cloudfront')
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')

    def declare_tested_service(self) -> str:
        return 'cloudfront'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        return \
        self.distribution_is_encrypted() + \
        self.distribution_is_field_level_encrypted() + \
        self.distribution_waf() + \
        self.distribution_security_tls1_1_or_higher() + \
        self.distribution_logging_is_enabled() + \
        self.distribution_viewer_is_encrypted()

    def distribution_is_encrypted(self):
        result = []
        #Get All Trails Description
        distribution_list = self.aws_cloudfront_client.list_distributions()
        #Get the Array and process each element
        distributions = distribution_list.get("DistributionList")
        distribution_items = distributions.get("Items")
        for distribution_meta in distribution_items:
            distributionId = distribution_meta["Id"]
            distributionDomainName = distribution_meta["DomainName"]
            for distribution_meta_items in distribution_meta["Origins"]["Items"]:
                if distribution_meta_items.get('CustomOriginConfig', {}).get('OriginProtocolPolicy') != "https-only":
                    result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "item_type" : "cloudfront",
                    "item" : distributionId,
                    "distribution_domain_name" : distributionDomainName,
                    "test_name" : 'distribution_is_encrypted',
                    "timestamp" : time.time()
                })
        if len(result) == 0:
            result.append({
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "item_type" : "cloudfront",
            "test_name": 'distribution_is_encrypted',
            "item": None,
            "timestamp": time.time()                    
            })
        return result
    
    def distribution_is_field_level_encrypted(self):
        result = []
        #Get All Trails Description
        distribution_list = self.aws_cloudfront_client.list_distributions()
        #Get the Array and process each element
        distributions = distribution_list.get("DistributionList")
        distribution_items = distributions.get("Items")
        for distribution_meta in distribution_items:
            distributionId = distribution_meta["Id"]
            distributionDomainName = distribution_meta["DomainName"]
            if distribution_meta.get('DefaultCacheBehavior',{}).get('FieldLevelEncryptionId') == "":
                result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item_type" : "cloudfront",
                "item" : distributionId,
                "distribution_domain_name" : distributionDomainName,
                "test_name" : 'distribution_is_field_level_encrypted',
                "timestamp" : time.time()
                })
        if len(result) == 0:
            result.append({
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "item_type" : "cloudfront",
            "test_name": 'distribution_is_field_level_encrypted',
            "item": None,
            "timestamp": time.time()                    
            })
        return result
    
    def distribution_waf(self):
        result = []
        #Get All Trails Description
        distribution_list = self.aws_cloudfront_client.list_distributions()
        #Get the Array and process each element
        distributions = distribution_list.get("DistributionList")
        distribution_items = distributions.get("Items")
        for distribution_meta in distribution_items:
            distributionId = distribution_meta["Id"]
            distributionDomainName = distribution_meta["DomainName"]
            if distribution_meta.get('WebACLId',{}) == "":
                result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item_type" : "cloudfront",
                "item" : distributionId,
                "distribution_domain_name" : distributionDomainName,
                "test_name" : 'distribution_waf',
                "timestamp" : time.time()
                })
        if len(result) == 0:
            result.append({
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "item_type" : "cloudfront",
            "test_name": 'distribution_waf',
            "item": None,
            "timestamp": time.time()                    
            })
        return result

    def distribution_security_tls1_1_or_higher(self):
        result = []
        #Get All Trails Description
        distribution_list = self.aws_cloudfront_client.list_distributions()
        #Get the Array and process each element
        distributions = distribution_list.get("DistributionList")
        distribution_items = distributions.get("Items")
        for distribution_meta in distribution_items:
            distributionId = distribution_meta["Id"]
            distributionDomainName = distribution_meta["DomainName"]
            for distribution_meta_items in distribution_meta["Origins"]["Items"]:
                
                if  "TLSv1" in distribution_meta_items.get('CustomOriginConfig',{}).get('OriginSslProtocols', {}).get('Items',{}):
                    result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "item_type" : "cloudfront",
                    "item" : distributionId,
                    "distribution_domain_name" : distributionDomainName,
                    "test_name" : 'distribution_security_tls1_1_or_higher',
                    "timestamp" : time.time()
                    })
        if len(result) == 0:
            result.append({
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "item_type" : "cloudfront",
            "test_name": 'distribution_security_tls1_1_or_higher',
            "item": None,
            "timestamp": time.time()                    
            })
        return result


    def distribution_logging_is_enabled(self):
        result = []
        #Get All Trails Description
        distribution_list = self.aws_cloudfront_client.list_distributions()
        #Get the Array and process each element
        distributions = distribution_list.get("DistributionList")
        distribution_items = distributions.get("Items")
        for distribution_meta in distribution_items:
            distributionId = distribution_meta["Id"]
            distributionDomainName = distribution_meta["DomainName"]
            distribution_config = self.aws_cloudfront_client.get_distribution_config(Id=distributionId)
            if distribution_config["DistributionConfig"]["Logging"]["Enabled"] == False:

                result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item_type" : "cloudfront",
                "item" : distributionId,
                "distribution_domain_name" : distributionDomainName,
                "test_name" : 'distribution_logging_is_enabled',
                "timestamp" : time.time()
                })
        if len(result) == 0:
            result.append({
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "item_type" : "cloudfront",
            "test_name": 'distribution_logging_is_enabled',
            "item": None,
            "timestamp": time.time()                    
            })
        return result

    def distribution_viewer_is_encrypted(self):
        result = []
        #Get All Trails Description
        distribution_list = self.aws_cloudfront_client.list_distributions()
        #Get the Array and process each element
        distributions = distribution_list.get("DistributionList")
        distribution_items = distributions.get("Items")
        for distribution_meta in distribution_items:
            distributionId = distribution_meta["Id"]
            distributionDomainName = distribution_meta["DomainName"]
            if  distribution_meta.get('DefaultCacheBehavior',{}).get('ViewerProtocolPolicy', {}) != "https-only":
                result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "item_type" : "cloudfront",
                "item" : distributionId,
                "distribution_domain_name" : distributionDomainName,
                "test_name" : 'distribution_viewer_is_encrypted',
                "timestamp" : time.time()
                })
        if len(result) == 0:
            result.append({
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "item_type" : "cloudfront",
            "test_name": 'distribution_viewer_is_encrypted',
            "item": None,
            "timestamp": time.time()                    
            })
        return result
    
