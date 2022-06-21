import time
import concurrent.futures
import boto3
import interfaces


class Tester(interfaces.TesterInterface):
    def __init__(self, region_name):
        self.aws_apigatewayv2_client = boto3.client('apigatewayv2', region_name=region_name)
        self.cache = {}
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.v2_domain_names = self._return_all_v2_domain_names()

    def declare_tested_service(self) -> str:
        return 'apigatewayv2'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        executor_list = []
        return_value = []

        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor_list.append(executor.submit(self.detect_apigateway_v2_apis_are_accepting_tls_1_2_or_higher))
            for future in executor_list:
                return_value += future.result()

        return return_value

    def _append_apigatewayv2_test_result(self, apigatewayv2_name, test_name, issue_status):
        return {
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": apigatewayv2_name,
            "item_type": "apigatewayv2",
            "test_name": test_name,
            "test_result": issue_status
        }

    def _return_all_v2_domain_names(self):
        response = self.aws_apigatewayv2_client.get_domain_names(
            MaxResults="100")
        domain_name = 'Items' in response and response['Items'] or []
        while 'NextToken' in response and response['NextToken']:
            response = self.aws_apigatewayv2_client.get_domain_names(
                MaxResults="100",
                NextToken=response['NextToken']
            )
            domain_name.extend(response['Items'])

        return domain_name

    def detect_apigateway_v2_apis_are_accepting_tls_1_2_or_higher(self):
        apigateway_v2_result = []
        test_name = 'aws_apigateway_v2_apis_are_accepting_tls_1_2_or_higher'
        for domain_name_dict in self.v2_domain_names:
            if 'DomainNameConfigurations' in domain_name_dict and domain_name_dict['DomainNameConfigurations']:
                issue_found = False
                for domain_name_configurations_dict in domain_name_dict['DomainNameConfigurations']:
                    if 'SecurityPolicy' in domain_name_configurations_dict and domain_name_configurations_dict[
                        'SecurityPolicy'] in ['TLS_1_0']:
                        issue_found = True
                        break
                if issue_found:
                    apigateway_v2_result.append(
                        self._append_apigatewayv2_test_result(domain_name_dict['DomainName'], test_name, 'issue_found'))
                else:
                    apigateway_v2_result.append(
                        self._append_apigatewayv2_test_result(domain_name_dict['DomainName'], test_name,
                                                              'no_issue_found'))

        return apigateway_v2_result

