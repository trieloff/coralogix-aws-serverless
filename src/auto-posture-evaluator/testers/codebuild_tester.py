import time
import boto3
import interfaces


class Tester(interfaces.TesterInterface):
    def __init__(self) -> None:
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.aws_codebuild_client = boto3.client('codebuild')
        self.codebuild_projects = self._get_all_codebuild_projects()

    def declare_tested_provider(self) -> str:
        return "aws"

    def declare_tested_service(self) -> str:
        return "codebuild"

    def run_tests(self) -> list:
        return \
            self.codebuild_project_build_artifacts_should_be_encrypted()

    def _get_all_codebuild_projects(self):
        projects = []
        paginator = self.aws_codebuild_client.get_paginator('list_projects')
        response_iterator = paginator.paginate()

        for page in response_iterator:
            projects.extend(page['projects'])

        return projects

    def _append_codebuild_test_results(self, item, item_type, test_name, issue_status):
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

    def codebuild_project_build_artifacts_should_be_encrypted(self):
        result = []
        test_name = "aws_codebuild_project_build_output_artifacts_should_be_encrypted"

        projects = self.codebuild_projects

        if projects:
            response = self.aws_codebuild_client.batch_get_projects(names=projects)
            projects_details = response['projects']

            for project in projects_details:
                project_arn = project['arn']

                artifacts_encryption_disable = project['artifacts'].get('encryptionDisabled')

                if artifacts_encryption_disable is not None:
                    if artifacts_encryption_disable:
                        result.append(self._append_codebuild_test_results(project_arn, "aws_codebuild_project", test_name, "issue_found"))
                    else:
                        result.append(self._append_codebuild_test_results(project_arn, "aws_codebuild_project", test_name, "no_issue_found"))
                else:
                    result.append(self._append_codebuild_test_results(project_arn, "aws_codebuild_project", test_name, "no_issue_found"))
        else: pass

        return result
