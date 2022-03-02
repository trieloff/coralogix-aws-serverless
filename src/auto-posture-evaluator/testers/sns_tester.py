import time
import boto3
import interfaces
import json


def _format_string_to_json(text):
    return json.loads(text)


def _check_sns_restriction_enabled(access_policy, is_topic):
    access_policy = _format_string_to_json(access_policy)
    restricted = True
    if is_topic:
        action_value = "SNS:Publish"
    else:
        action_value = "SNS:Subscribe"
    for statement in access_policy['Statement']:
        if 'Effect' in statement and statement['Effect'] == 'Deny':
            continue
        if 'Principal' in statement and 'AWS' in statement['Principal'] and statement['Principal'][
            'AWS'] == '*' and 'Condition' not in statement:
            if 'Action' in statement and statement['Action'] == action_value or action_value in statement['Action'] or \
                    statement['Action'] == '*':
                restricted = False
                break
    return restricted


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_sns_client = boto3.client('sns')
        self.cache = {}
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')

    def declare_tested_service(self) -> str:
        return 'sns'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        return self.detect_sns_has_restrictions_set_for_publishing() + \
               self.detect_sns_has_restrictions_set_for_subscription() + \
               self.detect_sns_topic_has_encryption_enabled()

    def _append_sns_test_result(self, sns_detail, is_topic, test_name, issue_status):
        return {
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": is_topic and sns_detail + " Topic" or sns_detail + "Subscription",
            "item_type": "sns",
            "test_name": test_name,
            "test_result": issue_status
        }

    def _return_all_the_topic_arns(self):
        response = self.aws_sns_client.list_topics()
        topic_arns = []
        topic_arns.extend(response['Topics'])
        # The API returns max of 100 topic arns in one call \
        # and need to paginate it using the next token sent.
        while len(response['Topics']) >= 100:
            response = self.aws_sns_client.list_topics(NextToken=response['NextToken'])
            topic_arns.extend(response['Topics'])
        return topic_arns

    def _return_all_the_subscription_arns(self):
        response = self.aws_sns_client.list_subscriptions()
        sub_arns = []
        sub_arns.extend(response['Subscriptions'])
        # The API returns max of 100 subscriptions arns in one call \
        # and need to paginate it using the next token sent in the previous response.
        while len(response['Subscriptions']) >= 100:
            response = self.aws_sns_client.list_subscriptions(NextToken=response['NextToken'])
            sub_arns.extend(response['Subscriptions'])
        return sub_arns

    def _restriction_check_on_topics(self, is_topic, test_name):
        result = []
        topic_arns = self._return_all_the_topic_arns()
        for topic in topic_arns:
            response = self.aws_sns_client.get_topic_attributes(
                TopicArn=topic['TopicArn']
            )
            if 'Attributes' in response and response['Attributes']:
                response = response['Attributes']
            else:
                continue
            if not _check_sns_restriction_enabled(response['Policy'], is_topic):
                result.append(self._append_sns_test_result(response['DisplayName'], True, test_name, "issue_found"))
            else:
                result.append(self._append_sns_test_result(response['DisplayName'], True, test_name, "no_issue_found"))
        return result

    def detect_sns_has_restrictions_set_for_publishing(self):
        test_name = "sns_has_restrictions_set_for_publishing"
        return self._restriction_check_on_topics(True, test_name)

    def detect_sns_has_restrictions_set_for_subscription(self):
        test_name = "sns_has_restrictions_set_for_subscription"
        return self._restriction_check_on_topics(False, test_name)

    def detect_sns_topic_has_encryption_enabled(self):
        test_name = "sns_topic_has_encryption_enabled"
        result = []
        topic_arns = self._return_all_the_topic_arns()
        for topic in topic_arns:
            response = self.aws_sns_client.get_topic_attributes(
                TopicArn=topic['TopicArn']
            )
            if 'Attributes' in response and response['Attributes']:
                response = response['Attributes']
            else:
                continue
            if 'KmsMasterKeyId' in response and not response['KmsMasterKeyId']:
                result.append(self._append_sns_test_result(response['DisplayName'], True, test_name, "issue_found"))
            elif 'KmsMasterKeyId' not in response:
                result.append(self._append_sns_test_result(response['DisplayName'], True, test_name, "issue_found"))
            else:
                result.append(self._append_sns_test_result(response['DisplayName'], True, test_name, "no_issue_found"))
        return result

