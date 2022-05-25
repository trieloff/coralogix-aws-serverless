import os
import time
import requests
import interfaces
import jmespath
from datetime import date, datetime


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.github_authorization_token = os.environ.get('AUTOPOSTURE_GITHUB_TOKEN')
        self.github_organizations = os.environ.get('AUTOPOSTURE_GITHUB_ORGANIZATIONS')
        self.deploy_keys_max_days_old = os.environ.get('AUTOPOSTURE_GITHUB_DEPLOY_KEYS_MAX_DAYS_OLD')
        self.max_admin_users = os.environ.get('AUTOPOSTURE_GITHUB_MAX_ADMIN_USERS')
        self.BASE_URL_ORGS = "https://api.github.com/orgs"
        self.BASE_URL_REPOS = "https://api.github.com/repos"
        self.BASE_URL_USERS = "http://api.github.com/users"

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
            },
            "two_factor_authentication_is_enforced": {
                "method": self.get_2fa_authentication_enforced,
                "result_item_type": "github_organization"
            },
            "base_permissions_not_set_to_admin": {
                "method": self.get_base_permission_not_admin,
                "result_item_type": "github_organization"
            },
            "members_can_not_create_public_repositories": {
                "method": self.get_members_can_not_create_public_repos,
                "result_item_type": "github_organization"
            },
            "organization's_domains_are_not_verified": {
                "method": self.get_org_domains_are_not_verified,
                "result_item_type": "github_organization"
            },
            "github_pages_is_disabled": {
                "method": self.get_github_pages_disabled,
                "result_item_type": "github_repository"
            },
            "members_without_signing_gpg_keys": {
                "method": self.get_members_without_gpg_keys,
                "result_item_type": "github_organization"
            },
            "code_security_alerts_are_enabled": {
                "method": self.get_code_security_alerts_are_enabled,
                "result_item_type": "github_repository"
            },
            "no_outside_collaborators_with_admin_permission": {
                "method": self.get_no_outside_collaborators_with_admin_permission,
                "result_item_type": "github_repository"
            },
            "pending_invitations_for_outside_collaborators_with_admin_permissions": {
                "method": self.get_pending_invitation_with_admin_permissions,
                "result_item_type": "github_repository"
            },
            "deploy_keys_are_fresh":{
                "method": self.get_deploy_keys_are_fresh,
                "result_item_type": "github_repository"
            },
            "sso_is_enabled":{
                "method": self.get_sso_enabled_for_organization,
                "result_item_type": "github_organization"
            },
            "all_repositories_monitored_for_code_vulnerabilities": {
                "method": self.get_all_repositories_monitored_for_code_vulnerabilities,
                "result_item_type": "github_organization"
            },
            "outside_collaborators_dont_have_admin_permissions": {
                "method": self.get_outside_collaborators_with_admin_permission,
                "result_item_type": "github_organization"
            },
            "third_party_apps_with_pullrequest_write_permission": {
                "method": self.get_third_party_apps_with_write_permission,
                "result_item_type": "github_organization"
            },
            "the_evidence_repositories_list_is_public": {
                "method": self.evidence_repositories_are_public,
                "result_item_type": "github_repository"
            },
            "no_vulnerabilities_were_found_on_the_repositories": {
                "method": self.get_vulnerabilities_found_on_repositories,
                "result_item_type": "github_repository"
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
        self._detect_valid_github_personal_access_token()
        organizations_list = self.get_organizations_list(
            self.github_organizations)
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
            raw_results = requests.get(
                headers=self.request_headers, url='https://api.github.com/user/orgs')
            raw_results_obj = raw_results.json()
            result = []
            for organization in raw_results_obj:
                result.append(organization["login"])
            return result

    def get_users_without_mfa(self, organization):
        result = []
        raw_api_result_all_users = requests.get(
            headers=self.request_headers, url=f"{self.BASE_URL_ORGS}/{organization}/members")
        raw_api_result_all_users_obj = raw_api_result_all_users.json()
        raw_api_result_2fa_disabled = requests.get(
            headers=self.request_headers, url=f"{self.BASE_URL_ORGS}/{organization}/members?filter=2fa_disabled")
        status_code = raw_api_result_2fa_disabled.status_code

        if status_code == 200:
            raw_api_result_2fa_disabled_obj = raw_api_result_2fa_disabled.json()
            for user in raw_api_result_all_users_obj:
                if user["login"] in [u.login for u in raw_api_result_2fa_disabled_obj]:
                    result.append(
                        {"item": user["login"] + "@@" + organization, "issue": True})
                else:
                    result.append(
                        {"item": user["login"] + "@@" + organization, "issue": False})
        else: pass

        return result

    def get_forkable_repositories(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}/repos"
        response = self._get_paginated_result(api)
        status_code = response['status_code']

        if status_code == 200:
            raw_api_result_obj = response['result']
            for repo in raw_api_result_obj:
                if repo["allow_forking"]:
                    result.append({"item": repo["name"], "issue": True})
                else:
                    result.append({"item": repo["name"], "issue": False})
        else: pass
        return result

    def check_for_too_many_admin_users(self, organization):
        result = []
        org_admins = []
        max_admin_users = int(self.max_admin_users) if self.max_admin_users else 15
        api = f"{self.BASE_URL_ORGS}/{organization}/members?role=admin"
        raw_api_result = requests.get(
            headers=self.request_headers, url=api)
        status_code = raw_api_result.status_code

        if status_code == 200:
            raw_api_result_obj = raw_api_result.json()
            for user in raw_api_result_obj:
                org_admins.append(user["login"])
            if len(org_admins) > max_admin_users:
                result.append({"item": organization, "issue": True})
            else:
                result.append({"item": organization, "issue": False})
        else: pass
        return result

    def _get_paginated_result(self, api):
        result = []
        page = 1
        has_page = True
        while has_page:
            raw_response = requests.get(headers=self.request_headers, url=f'{api}?page={page}&per_page=100')
            status_code = raw_response.status_code
            response_obj = raw_response.json()

            if status_code != 200:
                result.append(response_obj)
                break
            else:
                response_headers = raw_response.headers
                link = response_headers.get('Link')
                result.extend(response_obj)
            
                if link is not None:
                    if 'rel="next"' not in link:
                        has_page = False
                    else:
                        page += 1
                else:
                    has_page = False 
        
        response = {"status_code": status_code, "result": result}
        
        return response

    def get_2fa_authentication_enforced(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}"
        raw_api_response = requests.get(
            headers=self.request_headers, url=api)
        status_code = raw_api_response.status_code
        
        if status_code == 200:
            raw_api_response_obj = raw_api_response.json()
            enforced_2fa = raw_api_response_obj.get('two_factor_requirement_enabled')
            if enforced_2fa is not None:
                if enforced_2fa:
                    result.append({"item": organization, "issue": False})
                else: result.append({"item": organization, "issue": True})
            else: pass
        else: pass
        return result

    def get_base_permission_not_admin(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}"
        raw_api_response = requests.get(
            headers=self.request_headers, url=api)
        status_code = raw_api_response.status_code
        
        if status_code == 200:
            raw_api_response_obj = raw_api_response.json()
            default_repo_permission = raw_api_response_obj.get('default_repository_permission')

            if default_repo_permission is not None:
                if default_repo_permission.lower() == "admin":
                    result.append({"item": organization, "issue": True})
                else:
                    result.append({"item": organization, "issue": False})
            else: pass
        else: pass
        return result

    def get_members_can_not_create_public_repos(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}"
        raw_api_response = requests.get(
            headers=self.request_headers, url=api)
        status_code = raw_api_response.status_code

        if status_code == 200:
            org_details = raw_api_response.json()
            public_repo_create_permission = org_details.get('members_can_create_public_repositories')

            if public_repo_create_permission is not None:
                if public_repo_create_permission:
                    result.append({"item": organization, "issue": True})
                else:
                    result.append({"item": organization, "issue": False})
            else: pass
        else: pass

        return result

    def get_org_domains_are_not_verified(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}"
        raw_api_response = requests.get(
            headers=self.request_headers, url=api)
        status_code = raw_api_response.status_code

        if status_code == 200:
            org_details = raw_api_response.json()
            is_verifid = org_details.get('is_verified')
            if is_verifid is not None:
                if is_verifid:
                    result.append({"item": organization, "issue": False})
                else:
                    result.append({"item": organization, "issue": True})
            else: pass
        else: pass
        return result

    def get_github_pages_disabled(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}/repos"
        respone = self._get_paginated_result(api)
        status_code = respone['status_code']
        
        if status_code == 200:
            repos_details = respone['result']
            for repo in repos_details:
                repo_name = repo['name']
                has_pages = repo['has_pages']
                if has_pages:
                    result.append({"item": repo_name, "issue": True})
                else:
                    result.append({"item": repo_name, "issue": False})
        else: pass
        return result

    def get_members_without_gpg_keys(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}/members"
        response = self._get_paginated_result(api)
        status_code = response['status_code']
        
        if status_code == 200:
            org_members = response['result']
            members_without_gpg_keys_count = 0
            for member in org_members:
                username = member['login']
                api = f"{self.BASE_URL_USERS}/{username}/gpg_keys"
                response = self._get_paginated_result(api)
                status_code = response['status_code']

                if status_code == 200:
                    user_gpg_keys = response['result']
                    if len(user_gpg_keys) == 0:
                        members_without_gpg_keys_count += 1
                        break
                    else: pass
                else: pass
            if members_without_gpg_keys_count != 0:
                result.append({"item": organization, "issue": True})
            else:
                result.append({"item": organization, "issue": False})
        elif status_code == 302: pass
        elif status_code == 422: pass
        else: pass
        return result

    def get_code_security_alerts_are_enabled(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}/repos"
        response = self._get_paginated_result(api)
        status_code = response['status_code']
        
        if status_code == 200:
            repos_details = response['result']

            for repo in repos_details:
                repo_name = repo['name']
                owner = repo['owner']['login']
                api = f"{self.BASE_URL_REPOS}/{owner}/{repo_name}/vulnerability-alerts"
                raw_response = requests.get(
                    headers=self.request_headers, url=api)
                response_code = raw_response.status_code
                
                if response_code == 204:
                    result.append({"item": repo_name, "issue": False})
                elif response_code == 404:
                    response_obj = raw_response.json()
                    message = response_obj['message']
                    if message == 'Not Found': pass
                    else: result.append({"item": repo_name, "issue": True})
        
        else: pass
        return result

    def get_no_outside_collaborators_with_admin_permission(self, organization):
        result = []

        api = f"{self.BASE_URL_ORGS}/{organization}/outside_collaborators"
        response = self._get_paginated_result(api)
        status_code = response['status_code']

        if status_code == 200:
            outside_collaborators = response['result']
            collaborator_with_site_admin = False
            if len(outside_collaborators) > 0:
                for collaborator in outside_collaborators:
                    if collaborator['site_admin']:
                        collaborator_with_site_admin = True
                        break
                    else: pass
                if collaborator_with_site_admin:
                    result.append({"item": organization, "issue": True})
                else:
                    result.append({"item": organization, "issue": False})
            else:
                result.append({"item": organization, "issue": False})
        else: pass
        return result

    def get_pending_invitation_with_admin_permissions(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}/invitations"
        response = self._get_paginated_result(api)
        status_code = response['status_code']

        if status_code == 200:
            temp = response['result']
            invitations = {"result": temp}
            admin_invitation = jmespath.search("result[?role=='admin']", invitations)
        
            if len(admin_invitation) > 0:
                result.append({"item": organization, "issue": True})
            else:
                result.append({"item": organization, "issue": False})
        else: pass
        
        return result

    def get_deploy_keys_are_fresh(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}/repos"
        response = self._get_paginated_result(api)
        status_code = response['status_code']
        freshness_threshold = int(self.deploy_keys_max_days_old) if self.deploy_keys_max_days_old is not None else 30
        
        if status_code == 200:
            repos_details = response['result']
            for repo in repos_details:
                repo_name = repo['name']
                owner = repo['owner']['login']
                api = f"{self.BASE_URL_REPOS}/{owner}/{repo_name}/keys"
                response = self._get_paginated_result(api)
                status_code = response['status_code']
                
                if status_code == 200:
                    deploy_keys = response['result']
                    if len(deploy_keys) > 0:
                        found_old_key = False
                        for key in deploy_keys:
                            key_created_at = key['created_at']
                            key_created_date = key_created_at.split('T')[0]
                            key_created_at_obj = datetime.strptime(key_created_date, '%Y-%M-%d').date()
                            current_datetime = datetime.now().date()
                            time_diff = (current_datetime - key_created_at_obj).days

                            if time_diff > freshness_threshold:
                                found_old_key = True
                                break
                            else: pass
                        if found_old_key:
                            result.append({"item": repo_name, "issue": True})
                        else:
                            result.append({"item": repo_name, "issue": False})
                    else: pass
                else: pass
        else: pass
        return result

    def get_sso_enabled_for_organization(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}/credential-authorizations"
        raw_response = requests.get(headers=self.request_headers, url=api)
        status_code = raw_response.status_code

        if status_code == 200:
            org_auth_details = raw_response.json()

            if len(org_auth_details) > 0:
                result.append({"item": organization, "issue": False})
            else:
                result.append({"item": organization, "issue": True})
        else: pass

        return result

    def get_all_repositories_monitored_for_code_vulnerabilities(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}/repos"
        response = self._get_paginated_result(api)
        status_code = response['status_code']

        if status_code == 200:
            repos = response['result']
            for repo in repos:
                repo_name = repo['name']
                owner = repo['owner']['login']

                api = f"{self.BASE_URL_REPOS}/{owner}/{repo_name}/code-scanning/analyses"
                raw_response = requests.get(headers=self.request_headers, url=api)
                status_code = raw_response.status_code

                if status_code == 404:
                    result.append({"item": repo_name, "issue": False})
                elif status_code == 403:
                    result.append({"item": repo_name, "issue": True})
                elif status_code == 200:
                    result.append({"item": repo_name, "issue": True})
                else: pass
        else: pass
        return result

    def get_outside_collaborators_with_admin_permission(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}/repos"
        response = self._get_paginated_result(api)
        status_code = response['status_code']

        if status_code == 200:
            repos = response['result']
            for repo in repos:
                repo_name = repo['name']
                owner = repo['owner']['login']
                collaborators = []
                page = 10
                has_page = True
                while has_page:
                    api = f"{self.BASE_URL_REPOS}/{owner}/{repo_name}/collaborators?affiliation=outside&page={page}"
                    raw_response = requests.get(headers=self.request_headers, url=api)
                    pg_status_code = raw_response.status_code
                    response = raw_response.json()
                    response_headers = raw_response.headers
                        
                    if pg_status_code == 200: collaborators.extend(response)
                    elif pg_status_code == 403: pass
                    else: pass
                    
                    link = response_headers.get('Link')
                    if link is not None:
                        if 'rel="next"' not in link:
                            has_page = False
                        else:
                            page += 1
                    else:
                        has_page = False

                if len(collaborators) > 0:
                    outside_collab_with_admin = False
                    for collaborator in collaborators:
                        if collaborator['permissions']['admin']:
                            outside_collab_with_admin = True
                            break
                        else: pass
                
                    if outside_collab_with_admin:
                        result.append({"item": repo_name, "issue": True})
                    else:
                        result.append({"item": repo_name, "issue": False})
                else:
                    result.append({"item": repo_name, "issue": False})
        else: pass 
        
        return result

    def get_third_party_apps_with_write_permission(self, organization):
        result = []
        pg_result = []
        page = 1
        has_page = True
        while has_page:
            api = f"{self.BASE_URL_ORGS}/{organization}/installations?page={page}&per_page=1"
            raw_response = requests.get(headers=self.request_headers, url=api)
            response = raw_response.json()
            status_code = raw_response.status_code
            response_headers = raw_response.headers

            if status_code == 200:
                pg_result.extend(response['installations'])
            else:
                pg_result.append(response)
                break

            link = response_headers.get('Link')

            if link is not None:
                if 'rel="next"' not in link:
                    has_page = False
                else:
                    page += 1 
            else: has_page = False

        app_info = {"status_code": status_code, "result": pg_result}
        
        if app_info['status_code'] == 200:
            app_installations = app_info['result']
            if len(app_installations) > 0:
                apps_with_access_count = False
            
                for i in app_installations:
                    pullrequest = i['permissions'].get('pull_requests')

                    if pullrequest == 'write':
                        apps_with_access_count = True
                        break
                    else: pass
                if apps_with_access_count:
                    result.append({"item": organization, "issue": True})
                else:
                    result.append({"item": organization, "issue": False})
            else:
                result.append({"item": organization, "issue": False})
        else: pass
        return result

    def evidence_repositories_are_public(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}/repos"
        response = self._get_paginated_result(api)
        status_code = response['status_code']

        if status_code == 200:
            repos = response['result']
            for repo in repos:
                repo_name = repo['name']
                if not repo['private']:
                    result.append({"item": repo_name, "issue": True})
                else:
                    result.append({"item": repo_name, "issue": False})
        else: pass
        return result

    def get_vulnerabilities_found_on_repositories(self, organization):
        result = []
        api = f"{self.BASE_URL_ORGS}/{organization}/repos"
        response = self._get_paginated_result(api)
        status_code = response['status_code']

        if status_code == 200:
            repos = response['result']
            for repo in repos:
                repo_name = repo['name']
                owner = repo['owner']['login']

                api = f"{self.BASE_URL_REPOS}/{owner}/{repo_name}/code-scanning/alerts"
                raw_response = requests.get(headers=self.request_headers, url=api)
                status_code = raw_response.status_code
                
                if status_code == 403:
                   result.append({"item": repo_name, "issue": True})
                elif status_code == 404:
                    result.append({"item": repo_name, "issue": False})
                elif status_code == 200:
                    result.append({"item": repo_name, "issue": True})
                elif status_code == 304:
                    result.append({"item": repo_name, "issue": False})
                else:
                    pass
        else: pass
        return result

    def _detect_valid_github_personal_access_token(self):
        response = requests.get(url=f"{self.BASE_URL_USERS}", headers=self.request_headers)
        status_code = response.status_code

        if status_code != 200:
            message = response.json().get("message")
            raise Exception(message)
        else: pass
