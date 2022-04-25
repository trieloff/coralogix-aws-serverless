import time
import boto3
import interfaces
import json


def _format_string_to_json(text):
    return json.loads(text)


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_ses_client = boto3.client('ses')
        self.cache = {}
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.all_ses_identities = self._return_all_ses_identities()

    def declare_tested_service(self) -> str:
        return 'ses'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        return self.detect_ses_domain_identity_should_be_verified() + \
               self.detect_ses_exposed_ses_identities() + \
               self.detect_ses_domain_identity_should_use_dkim_signatures()

    def _append_ses_test_result(self, domain_identity, test_name, issue_status):
        return {
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": domain_identity,
            "item_type": "ses",
            "test_name": test_name,
            "test_result": issue_status
        }

    def _return_all_ses_identities(self, all=False):
        attributes_to_pass = {'MaxItems': 100}
        if not all:
            attributes_to_pass['IdentityType'] = 'Domain'
        ses_identities = []
        response = self.aws_ses_client.list_identities(**attributes_to_pass)
        ses_identities.extend(response['Identities'])
        while 'NextToken' in response and response['NextToken']:
            response = self.aws_ses_client.list_identities(**attributes_to_pass,
                                                           NextToken=response['NextToken'])
            ses_identities.extend(response['Identities'])
        return ses_identities

    def detect_ses_domain_identity_should_be_verified(self):
        dkim_result = []
        test_name = 'ses_domain_identity_should_be_verified'
        dkim_attributes_res = self.aws_ses_client.get_identity_dkim_attributes(Identities=self.all_ses_identities)
        if dkim_attributes_res and 'DkimAttributes' in dkim_attributes_res and dkim_attributes_res[
            'DkimAttributes']:
            dkim_attributes = dkim_attributes_res['DkimAttributes']
            for domain_identity in self.all_ses_identities:
                if domain_identity in dkim_attributes and dkim_attributes[domain_identity] and \
                        dkim_attributes[domain_identity]['DkimVerificationStatus'].lower() == 'success':
                    dkim_result.append(self._append_ses_test_result(domain_identity, test_name, 'no_issue_found'))
                else:
                    dkim_result.append(self._append_ses_test_result(domain_identity, test_name, 'issue_found'))
        return dkim_result

    def detect_ses_exposed_ses_identities(self):
        ses_policy_result = []
        test_name = 'ses_exposed_ses_identities'
        for domain_identity in self._return_all_ses_identities(all=True):
            ses_policies = self.aws_ses_client.list_identity_policies(Identity=domain_identity)
            issue_found = False
            if ses_policies['PolicyNames']:
                all_policy_details = self.aws_ses_client.get_identity_policies(Identity=domain_identity,
                                                                               PolicyNames=ses_policies['PolicyNames'])

                if 'Policies' in all_policy_details and all_policy_details['Policies']:
                    policy_detail_dict = all_policy_details['Policies']
                    for policy_name in ses_policies['PolicyNames']:
                        if issue_found:
                            break
                        policy_details = _format_string_to_json(policy_detail_dict[policy_name])
                        for statement_dict in policy_details['Statement']:
                            if (statement_dict['Principal'] == '*' or (
                                    'AWS' in statement_dict['Principal'] and statement_dict['Principal'][
                                'AWS'] == '*')) and not ('Condition' in statement_dict and statement_dict[
                                'Condition']) and 'Effect' in statement_dict and \
                                    statement_dict['Effect'].lower() == 'allow' and (
                                    statement_dict['Action'] in ['ses:SendEmail',
                                                                 'ses:SendRawEmail'] or 'ses:SendEmail' in
                                    statement_dict['Action'] or 'ses:SendRawEmail' in statement_dict['Action']):
                                issue_found = True
                                break
            if issue_found:
                ses_policy_result.append(self._append_ses_test_result(domain_identity, test_name, 'issue_found'))
            else:
                ses_policy_result.append(self._append_ses_test_result(domain_identity, test_name, 'no_issue_found'))
        return ses_policy_result

    def detect_ses_domain_identity_should_use_dkim_signatures(self):
        dkim_signature_result = []
        test_name = 'ses_domain_identity_should_use_dkim_signatures'
        dkim_attributes_res = self.aws_ses_client.get_identity_dkim_attributes(Identities=self.all_ses_identities)
        if dkim_attributes_res and 'DkimAttributes' in dkim_attributes_res and dkim_attributes_res[
            'DkimAttributes']:
            dkim_attributes = dkim_attributes_res['DkimAttributes']
            for domain_identity in self.all_ses_identities:
                if domain_identity in dkim_attributes and dkim_attributes[domain_identity] and \
                        dkim_attributes[domain_identity]['DkimEnabled']:
                    dkim_signature_result.append(
                        self._append_ses_test_result(domain_identity, test_name, 'no_issue_found'))
                else:
                    dkim_signature_result.append(
                        self._append_ses_test_result(domain_identity, test_name, 'issue_found'))
        return dkim_signature_result

