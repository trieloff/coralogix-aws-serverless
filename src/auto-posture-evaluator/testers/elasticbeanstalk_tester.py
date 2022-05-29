import time
from traceback import print_tb
import boto3
import jmespath
import interfaces

class Tester(interfaces.TesterInterface):
    def __init__(self) -> None:
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.aws_elasticbeanstalk_client = boto3.client('elasticbeanstalk')
        self.elasticbeanstalk_enviroments = self._get_all_environemnts()

    def declare_tested_provider(self) -> str:
        return "aws"
    
    def declare_tested_service(self) -> str:
        return "elasticbeanstalk"
    
    def run_tests(self) -> list:
        return \
            self.application_environment_should_have_load_balancer_access_logs() + \
            self.enhanced_health_enabled() + \
            self.application_env_has_managed_updates_enabled() + \
            self.detect_environment_notification_configured()

    def _append_elasticbeanstalk_test_result(self, item, item_type, test_name, issue_status):
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

    def _get_all_environemnts(self):
        environments = []
        paginator = self.aws_elasticbeanstalk_client.get_paginator('describe_environments')
        response_iterator = paginator.paginate()

        for page in response_iterator:
            environments.extend(page['Environments'])
        
        return environments

    def application_environment_should_have_load_balancer_access_logs(self):
        result = []
        test_name = "elasticbeanstalk_application_environment_should_have_load_balancer_access_logs"
        environments = self.elasticbeanstalk_enviroments

        for env in environments:
            application_name = env['ApplicationName']
            environment_name = env['EnvironmentName']

            response = self.aws_elasticbeanstalk_client.describe_configuration_settings(ApplicationName=application_name, EnvironmentName=environment_name)
            configuration_settings = {"configuration_settings": response['ConfigurationSettings']}
            filtered_response = jmespath.search("configuration_settings[*].OptionSettings[?(OptionName==`AccessLogsS3Enabled`)].Value | []", configuration_settings)

            access_logs_enabled = filtered_response
            if not access_logs_enabled: 
                result.append(self._append_elasticbeanstalk_test_result(environment_name, "elasticbeanstalk_application_environment", test_name, "issue_found"))
            elif access_logs_enabled[0] == "false":
                result.append(self._append_elasticbeanstalk_test_result(environment_name, "elasticbeanstalk_application_environment", test_name, "issue_found"))
            else:
                result.append(self._append_elasticbeanstalk_test_result(environment_name, "elasticbeanstalk_application_environment", test_name, "no_issue_found"))
        
        return result

    def enhanced_health_enabled(self):
        result = []
        test_name = "enhanced_health_reporting_enabled"
        environments = self.elasticbeanstalk_enviroments
        
        filtered_environments = list(filter(lambda env: env['Status'] == "Ready" or env['Status'] == "Updating" or env["Status"] == "Launching" or env["Status"] == "LinkingFrom" or env["Status"] == "LinkingTo", environments))

        for env in filtered_environments:
            env_name = env['EnvironmentName']
            health_status = env.get('HealthStatus')

            if health_status is not None:
                result.append(self._append_elasticbeanstalk_test_result(env_name, "elasticbeanstalk_application_environment", test_name, "no_issue_found"))
            else:
                result.append(self._append_elasticbeanstalk_test_result(env_name, "elasticbeanstalk_application_environment", test_name, "issue_found"))
        
        return result

    def application_env_has_managed_updates_enabled(self):
        result = []
        test_name = "application_environment_should_have_managed_platform_updates_enabled"
        environments = self.elasticbeanstalk_enviroments
        
        for env in environments:
            env_name = env['EnvironmentName']
            app_name = env['ApplicationName']

            response = self.aws_elasticbeanstalk_client.describe_configuration_settings(ApplicationName=app_name, EnvironmentName=env_name)
            configuration_settings = {"ConfigurationSettings" : response["ConfigurationSettings"]}
            temp = jmespath.search("ConfigurationSettings[*].OptionSettings[?OptionName==`ManagedActionsEnabled`] | []", configuration_settings)
            if len(temp) > 0:
                managed_actions = temp[0]['Value']
                if managed_actions == "true":
                    result.append(self._append_elasticbeanstalk_test_result(env_name, "elasticbeanstalk_application_environment", test_name, "no_issue_found"))
                else: 
                    result.append(self._append_elasticbeanstalk_test_result(env_name, "elasticbeanstalk_application_environment", test_name, "issue_found"))
            else: pass
        
        return result

    def detect_environment_notification_configured(self):
        result = []
        test_name = "environment_notifications_should_be_configured"
        environments = self.elasticbeanstalk_enviroments
        
        for env in environments:
            env_name = env['EnvironmentName']
            app_name = env['ApplicationName']

            response = self.aws_elasticbeanstalk_client.describe_configuration_settings(ApplicationName=app_name, EnvironmentName=env_name)
            configuration_settings = {"ConfigurationSettings" : response["ConfigurationSettings"]}
            temp = jmespath.search("ConfigurationSettings[*].OptionSettings[?OptionName==`Notification Endpoint`].Value | []", configuration_settings)

            if not temp:
                result.append(self._append_elasticbeanstalk_test_result(env_name, "elasticbeanstalk_application_environment", test_name, "issue_found"))
            else:
                result.append(self._append_elasticbeanstalk_test_result(env_name, "elasticbeanstalk_application_environment", test_name, "no_issue_found"))

        return result