import os
import time
import requests
import interfaces


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.github_authorization_token = os.environ.get('AUTOPOSTURE_GITHUB_TOKEN')
        self.github_organizations = os.environ.get('AUTOPOSTURE_GITHUB_ORGANIZATIONS')
        self.tests = {
            "users_without_mfa": {
                "method": self.get_users_without_mfa,
                "result_item_type": "github_user"
            },
            "forking_enabled_repos": {
                "method": self.get_forkable_repositories,
                "result_item_type": "github_repository"
            },
            "too_many_admin_users_per_org": {
                "method": self.check_for_too_many_admin_users,
                "result_item_type": "github_organization"
            }
        }
        self.request_headers = {
            "Authorization": "token " + self.github_authorization_token,
            "Accept": "application/vnd.github.v3+json"
        }

    def declare_tested_service(self) -> str:
        return 'github'

    def declare_tested_provider(self) -> str:
        return 'github'

    def run_tests(self) -> list:
        results = []
        organizations_list = self.get_organizations_list(self.github_organizations)
        for test_name in self.tests.keys():
            for organization in organizations_list:
                raw_results = self.tests[test_name]["method"](organization)
                if len(raw_results) > 0:
                    for item in raw_results:
                        if item["issue"]:
                            results.append({
                                "timestamp": time.time(),
                                "account": organization,
                                "item": item["item"],
                                "item_type": self.tests[test_name]["result_item_type"],
                                "test_name": test_name,
                                "test_result": "issue_found"
                            })
                        else:
                            results.append({
                                "timestamp": time.time(),
                                "account": organization,
                                "item": item["item"],
                                "item_type": self.tests[test_name]["result_item_type"],
                                "test_name": test_name,
                                "test_result": "no_issue_found"})

        return results

    def get_organizations_list(self, organizations):
        if organizations is not None:
            return str(organizations).split(',')
        else:
            raw_results = requests.get(headers=self.request_headers, url='https://api.github.com/user/orgs')
            raw_results_obj = raw_results.json()
            result = []
            for organization in raw_results_obj:
                result.append(organization["login"])
            return result

    def get_users_without_mfa(self, organization):
        result = []
        raw_api_result_all_users = requests.get(headers=self.request_headers, url='https://api.github.com/orgs/' + organization + '/members')
        raw_api_result_all_users_obj = raw_api_result_all_users.json()
        raw_api_result_2fa_disabled = requests.get(headers=self.request_headers, url='https://api.github.com/orgs/' + organization + '/members?filter=2fa_disabled')
        raw_api_result_2fa_disabled_obj = raw_api_result_2fa_disabled.json()
        for user in raw_api_result_all_users_obj:
            if user["login"] in [u.login for u in raw_api_result_2fa_disabled_obj]:
                result.append({"item": user["login"] + "@@" + organization, "issue": True})
            else:
                result.append({"item": user["login"] + "@@" + organization, "issue": False})

        return result

    def get_forkable_repositories(self, organization):
        result = []
        raw_api_result = requests.get(headers=self.request_headers, url='https://api.github.com/orgs/' + organization + '/repos')
        raw_api_result_obj = raw_api_result.json()
        for repo in raw_api_result_obj:
            if repo["allow_forking"]:
                result.append({"item": repo["name"], "issue": True})
            else:
                result.append({"item": repo["name"], "issue": False})

        return result

    def check_for_too_many_admin_users(self, organization):
        result = []
        org_admins = []
        raw_api_result = requests.get(headers=self.request_headers, url='https://api.github.com/orgs/' + organization + '/members?role=admin')
        raw_api_result_obj = raw_api_result.json()
        for user in raw_api_result_obj:
            org_admins.append(user["login"])
        if len(org_admins) > 15:
            result.append({"item": organization, "issue": True})
        else:
            result.append({"item": organization, "issue": False})

        return result
