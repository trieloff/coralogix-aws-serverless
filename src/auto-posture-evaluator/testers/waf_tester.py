import time

import boto3
import interfaces




class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_waf_client = boto3.client('wafv2')
        # By default all cloudfront web acls will lies in  us-east-1 region so region_name is required.
        self.aws_waf_global_client = boto3.client('wafv2', region_name='us-east-1')
        self.cache = {}
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.regional_scope = 'REGIONAL'
        self.cloudfront_scope = 'CLOUDFRONT'
        self.regional_web_acls, self.cloudfront_web_acls = self._return_all_web_acls()

    def declare_tested_service(self) -> str:
        return 'waf'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        regional_waf_dict = self._get_all_rule_sets(self.regional_scope, self.aws_waf_client, self.regional_web_acls)
        cloudfront_waf_dict = self._get_all_rule_sets(self.cloudfront_scope, self.aws_waf_global_client,
                                                      self.cloudfront_web_acls)

        return self.detect_aws_managed_rules_known_bad_inputs_ruleset(regional_waf_dict, cloudfront_waf_dict) + \
               self.detect_aws_managed_rule_group_anonymous_ip_list(regional_waf_dict, cloudfront_waf_dict)

    def _append_waf_test_result(self, waf, test_name, issue_status) -> dict:
        return {
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": waf,
            "item_type": "waf",
            "test_name": test_name,
            "test_result": issue_status
        }

    def _return_web_acls_based_on_scope(self, scope, waf_client) -> list:
        web_acls = []
        response = waf_client.list_web_acls(Scope=scope, Limit=100)
        if 'WebACLs' in response and response['WebACLs']:
            web_acls.extend(response['WebACLs'])
        while 'NextMarker' in response and response['NextMarker']:
            response = waf_client.list_web_acls(Scope=scope, Limit=100,
                                                NextMarker=response['NextMarker'])
            web_acls.extend(response['WebACLs'])
        return web_acls

    def _return_all_web_acls(self):
        regional_web_acls = self._return_web_acls_based_on_scope(self.regional_scope, self.aws_waf_client)
        cloudfront_web_acls = self._return_web_acls_based_on_scope(self.cloudfront_scope, self.aws_waf_global_client)

        return regional_web_acls, cloudfront_web_acls

    def _get_all_rule_sets(self, scope, client, web_acls) -> list:
        result = []
        for web_acl in web_acls:
            response = client.get_web_acl(
                Name=web_acl['Name'],
                Scope=scope,
                Id=web_acl['Id']
            )
            result.append(response['WebACL'])
        return result

    def _find_waf_issues(self, scope, issue_type, waf_acls, test_name) -> list:
        result = []
        for value in waf_acls:
            if 'Rules' in value and value['Rules']:
                issue_found = True
                for rule in value['Rules']:
                    if rule['Name'] == issue_type:
                        issue_found = False
                        break
                if issue_found:
                    result.append(self._append_waf_test_result(value["Name"] + '@@' + scope, test_name, 'issue_found'))
                else:
                    result.append(
                        self._append_waf_test_result(value["Name"] + '@@' + scope, test_name, 'no_issue_found'))

            else:
                result.append(self._append_waf_test_result(value["Name"] + '@@' + scope, test_name, 'issue_found'))

        return result

    def detect_aws_managed_rules_known_bad_inputs_ruleset(self, regional_waf, cloudfront_waf) -> list:
        rule_type_to_check = 'AWS-AWSManagedRulesKnownBadInputsRuleSet'
        test_name = 'aws_waf_web_acl_should_include_aws_managed_rules_against_log4shell'
        regional_waf_result = self._find_waf_issues(self.regional_scope, rule_type_to_check, regional_waf, test_name)
        cloudfront_waf_result = self._find_waf_issues(self.cloudfront_scope, rule_type_to_check,
                                                      cloudfront_waf, test_name)

        return regional_waf_result + cloudfront_waf_result

    def detect_aws_managed_rule_group_anonymous_ip_list(self, regional_waf, cloudfront_waf) -> list:
        rule_type_to_check = 'AWS-AWSManagedRulesAnonymousIpList'
        test_name = 'aws_waf_web_acl_should_include_managed_rule_group_anonymous_ip_list'
        regional_waf_result = self._find_waf_issues(self.regional_scope, rule_type_to_check, regional_waf, test_name)
        cloudfront_waf_result = self._find_waf_issues(self.cloudfront_scope, rule_type_to_check,
                                                      cloudfront_waf, test_name)

        return regional_waf_result + cloudfront_waf_result

