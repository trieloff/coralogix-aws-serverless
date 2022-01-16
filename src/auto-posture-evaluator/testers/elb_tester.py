from json import load
import time
from typing import Dict, List
import interfaces
import boto3
import jmespath

class Tester(interfaces.TesterInterface):
    def __init__(self) -> None:
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.aws_elbs_client = boto3.client('elb')
        self.aws_elbsv2_client = boto3.client('elbv2')
        self.elbs = self._get_all_elb()
        self.elbsv2 = self._get_all_elbv2()
        self.cipher_suites = self._get_cipher_suite_details()
        self.latest_security_policies = self._get_aws_latest_security_policies()

    def declare_tested_service(self) -> str:
        return "elb"

    def declare_tested_provider(self) -> str:
        return "aws"

    def run_tests(self) -> list:
        
        return \
            self.get_elbv2_internet_facing() + \
            self.get_elbv2_generating_access_log() + \
            self.get_alb_using_secure_listener() + \
            self.get_elb_generating_access_log() + \
            self.get_elb_listeners_using_tls() + \
            self.get_elb_listeners_securely_configured() + \
            self.get_elb_has_secure_ssl_protocol() + \
            self.get_elb_security_policy_secure_ciphers() + \
            self.get_elbv2_using_latest_security_policy()
    
    def _get_all_elbv2(self) -> List:
        elbs = self.aws_elbsv2_client.describe_load_balancers()
        return elbs['LoadBalancers']
    
    def _get_all_elb(self) -> List:
        elbs = self.aws_elbs_client.describe_load_balancers()
        return elbs['LoadBalancerDescriptions']

    def _get_aws_latest_security_policies(self) -> List:
        policies = ['ELBSecurityPolicy-2016-08', 'ELBSecurityPolicy-FS-2018-06']
        return policies

    def _get_cipher_suite_details(self) -> Dict:
        cipher_suites = { 
            'AES128-GCM-SHA256' : 'weak', 'ECDHE-ECDSA-AES256-SHA': 'weak', 'ECDHE-ECDSA-AES256-GCM-SHA384': 'recommended', 'AES128-SHA': 'weak',
            'ECDHE-RSA-AES128-SHA': 'weak', 'ECDHE-ECDSA-AES128-SHA256': 'weak', 'ECDHE-RSA-AES128-GCM-SHA256': 'secure', 'ECDHE-RSA-AES256-SHA384': 'weak',
            'AES256-GCM-SHA384': 'weak', 'ECDHE-RSA-AES128-SHA256': 'weak', 'AES256-SHA256' : 'weak', 'ECDHE-ECDSA-AES256-SHA384': 'weak', 
            'AES128-SHA256' : 'weak', 'ECDHE-RSA-AES256-GCM-SHA384': 'secure', 'ECDHE-ECDSA-AES128-SHA': 'weak', 'AES256-SHA': 'weak', ''
            'ECDHE-ECDSA-AES128-GCM-SHA256': 'recommended', 'ECDHE-RSA-AES256-SHA': 'weak'
            }
        return cipher_suites

    def get_elbv2_internet_facing(self) -> List: 
        elbs = self.elbsv2
        test_name = "elbv2_is_not_internet_facing"
        result = []

        for elb in elbs:
            load_balancer_arn = elb['LoadBalancerArn']
            if elb['Scheme'] == 'internet-facing':
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": load_balancer_arn,
                    "item_type": "aws_elbv2",
                    "test_name": test_name,
                    "test_result": "issue_found"
                })
            else:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": load_balancer_arn,
                    "item_type": "aws_elbv2",
                    "test_name": test_name,
                    "test_result": "no_issue_found"
                })
        
        return result
    
    def get_elb_generating_access_log(self) -> List:
        elbs = self.elbs
        test_name = "elb_is_generating_access_log"
        result = []

        for elb in elbs:
            load_balancer_name = elb['LoadBalancerName']
            response = self.aws_elbs_client.describe_load_balancer_attributes(LoadBalancerName=load_balancer_name)
            if response['LoadBalancerAttributes']['AccessLog']['Enabled']:
                # no issue
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": load_balancer_name,
                    "item_type": "aws_elb",
                    "test_name": test_name,
                    "test_result": "no_issue_found"
                })
            else:
                # issue
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": load_balancer_name,
                    "item_type": "aws_elb",
                    "test_name": test_name,
                    "test_result": "issue_found"
                })
        
        return result
    
    def get_alb_using_secure_listener(self) -> List:
        test_name = "alb_is_using_secure_listeners"
        elbs = self.elbsv2
        result = []

        for elb in elbs:
            # check elbv2 type and only let ALB pass
            if elb['Type'] == "application":
                load_balancer_arn = elb['LoadBalancerArn']
                response = self.aws_elbsv2_client.describe_listeners(LoadBalancerArn=load_balancer_arn)
                listeners = response['Listeners']
                secure_listener_count = 0
                for listener in listeners:
                    if listener['Protocol'] == "HTTPS":
                        secure_listener_count += 1
                
                if secure_listener_count == len(listeners):
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": load_balancer_arn,
                        "item_type": "aws_elbv2",
                        "test_name": test_name,
                        "test_result": "no_issue_found"
                    })
                else:
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": load_balancer_arn,
                        "item_type": "aws_elbv2",
                        "test_name": test_name,
                        "test_result": "issue_found"
                    })
            else:
                continue
        
        return result
    
    def get_elbv2_generating_access_log(self) -> List:
        test_name = "elbv2_is_generating_access_logs"
        result = []
        elbs = self.elbsv2

        for elb in elbs:
            elb_arn = elb['LoadBalancerArn']
            elb_type = elb['Type']

            if elb_type == 'application' or elb_type == 'network':
                elb_attributes = self.aws_elbsv2_client.describe_load_balancer_attributes(LoadBalancerArn=elb_arn)
                attributes = elb_attributes['Attributes']
                for i in attributes:
                    if i['Key'] == 'access_logs.s3.enabled':
                        if i['Value'] == 'false':
                            result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "timestamp": time.time(),
                            "item": elb_arn,
                            "item_type": "aws_elbv2",
                            "test_name": test_name,
                            "test_result": "issue_found"
                            })
                        else:
                            result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "timestamp": time.time(),
                            "item": elb_arn,
                            "item_type": "aws_elbv2",
                            "test_name": test_name,
                            "test_result": "no_issue_found"
                            })
                        break
                    else: pass
            else:
                # access log / vpc flow logs
                arn_split = elb_arn.split(':')
                temp = arn_split[-1]
                description_temp = temp.split('loadbalancer/')
                network_interface_description = 'ELB' + ' ' + description_temp[-1]
                ec2_client = boto3.client('ec2')
                response = ec2_client.describe_network_interfaces(Filters=[{'Name' : 'description', 'Values' : [network_interface_description]}])
                network_interfaces = response['NetworkInterfaces']
                interface_ids = []
                for interface in network_interfaces:
                    interface_ids.append(interface['NetworkInterfaceId'])

                has_flow_logs = 0
                for id in interface_ids:
                    response = ec2_client.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values' : [id]}])
                    flow_logs = response['FlowLogs']
                    if len(flow_logs) > 0:
                        has_flow_logs += 1
                    
                if len(interface_ids) == has_flow_logs:
                    # no issue
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": elb_arn,
                        "item_type": "aws_elbv2",
                        "test_name": test_name,
                        "test_result": "no_issue_found"
                    })
                else:
                    # issue
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": elb_arn,
                        "item_type": "aws_elbv2",
                        "test_name": test_name,
                        "test_result": "issue_found"
                    })                
        return result

    def get_elb_listeners_using_tls(self) -> List:
        test_name = "elb_listeners_using_tls_v1.2"
        result = []
        elbs = self.elbs

        for elb in elbs:
            elb_name = elb['LoadBalancerName']
            listeners = elb['ListenerDescriptions']
            secure_listeners_count = 0
            for listener in listeners:
                policy_names = listener['PolicyNames']

                if len(policy_names) > 0:
                    response = self.aws_elbs_client.describe_load_balancer_policies(PolicyNames=policy_names, LoadBalancerName=elb_name)
                    policy_descriptions = response['PolicyDescriptions']

                    found_tls_v12_count = 0
                        # look into policy attrs
                    for policy_description in policy_descriptions:
                        policy_attrs = policy_description['PolicyAttributeDescriptions']
                        for attr in policy_attrs:
                            if attr['AttributeName'] == 'Protocol-TLSv1.2' and attr['AttributeValue'] == 'true':
                                found_tls_v12_count += 1
                                break
                    if found_tls_v12_count == len(policy_descriptions):
                        secure_listeners_count += 1
                else: pass
          
            if secure_listeners_count == len(listeners):
                # secure
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": elb_name,
                    "item_type": "aws_elb",
                    "test_name": test_name,
                    "test_result": "no_issue_found"
                })
            else:
                # issue found
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": elb_name,
                    "item_type": "aws_elb",
                    "test_name": test_name,
                    "test_result": "issue_found"
                })
        return result

    def get_elb_listeners_securely_configured(self) -> List:
        test_name = "elb_listeners_securely_configurd"
        result = []

        elbs = self.elbs

        for elb in elbs:
            listeners = elb['ListenerDescriptions']
            loab_balancer_name = elb['LoadBalancerName']
            secure_listeners = 0
            for i in listeners:
                listener = i['Listener']
                if listener['InstanceProtocol'] == 'HTTPS' and listener['Protocol'] == 'HTTPS':
                    # secure
                    secure_listeners += 1
                elif listener['InstanceProtocol'] == 'SSL' and listener['Protocol'] == 'SSL':
                    # secure
                    secure_listeners += 1
                elif listener['InstanceProtocol'] == 'HTTPS' and listener['Protocol'] == 'SSL':
                    # secure
                    secure_listeners += 1
                elif listener['InstanceProtocol'] == 'SSL' and listener['Protocol'] == 'HTTPS':
                    # secure
                    secure_listeners += 1
                else: pass
            if len(listeners) == secure_listeners:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": loab_balancer_name,
                    "item_type": "aws_elb",
                    "test_name": test_name,
                    "test_result": "no_issue_found"
                })
            else:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": loab_balancer_name,
                    "item_type": "aws_elb",
                    "test_name": test_name,
                    "test_result": "issue_found"
                })
        
        return result

    def get_elb_security_policy_secure_ciphers(self) -> List:
        elbs = self.elbs
        test_name = "elb_security_policy_does_not_contain_any_insecure_ciphers"
        result = []
        elb_with_issue = []
        all_elbs = []
        for elb in elbs:
            # get policies 
            load_balancer_name = elb['LoadBalancerName']
            all_elbs.append(load_balancer_name)

            listeners = elb['ListenerDescriptions']
            listener_policies = []

            for listener in listeners:
                listener_policies.extend(listener['PolicyNames'])
            
            if len(listener_policies) > 0:
                response = self.aws_elbs_client.describe_load_balancer_policies(PolicyNames=listener_policies)
                query_result = jmespath.search("PolicyDescriptions[].PolicyAttributeDescriptions[?AttributeValue=='true'].AttributeName", response)
                all_attrs = []

                for i in query_result:
                    all_attrs.extend(i)
                unique_set = list(set(all_attrs))
                cipher_suites = self.cipher_suites
                for i in unique_set:
                    if i.startswith('Protocol') or i.startswith('protocol'): pass
                    elif i == 'Server-Defined-Cipher-Order': pass
                    elif cipher_suites[i] == 'insecure':
                        elb_with_issue.append(load_balancer_name)
                        break
                    else: pass
            else:
                elb_with_issue.append(load_balancer_name)
        all_elbs_set = set(all_elbs)
        elb_with_issue_set = set(elb_with_issue)
        elb_with_no_issue_set = all_elbs_set.difference(elb_with_issue)

        for i in elb_with_issue_set:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "aws_elb",
                "test_name": test_name,
                "test_result": "issue_found"
            })

        for i in elb_with_no_issue_set:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "aws_elb",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
        return result

    def get_elb_has_secure_ssl_protocol(self) -> List:
        test_name = "elb_has_secure_ssl_protocol"
        elbs = self.elbs
        result = []

        for elb in elbs:
            load_balancer_name = elb['LoadBalancerName']
            ssl_policies_count = len(elb['Policies']['OtherPolicies'])
            response = self.aws_elbs_client.describe_load_balancer_policies(LoadBalancerName=load_balancer_name)
            query_result = jmespath.search("PolicyDescriptions[].PolicyAttributeDescriptions[?AttributeValue=='true'].AttributeName", response)
            ssl_with_issue = 0
            for attrs in query_result:
                for attr in attrs:
                    if attr.startswith('Protocol'): pass
                    elif attr == 'Server-Defined-Cipher-Order': pass
                    else:
                        if self.cipher_suites[attr] == 'insecure':
                            ssl_with_issue += 1
                            break
            if ssl_policies_count == ssl_with_issue:
                # insecure
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": load_balancer_name,
                    "item_type": "aws_elb",
                    "test_name": test_name,
                    "test_result": "issue_found"
                })
            else:
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": load_balancer_name,
                    "item_type": "aws_elb",
                    "test_name": test_name,
                    "test_result": "no_issue_found"
                })
        return result

    def get_elbv2_using_latest_security_policy(self) -> List:
        test_name = "elbv2_using_latest_security_policy"
        elbv2 = self.elbsv2
        latest_security_policies = self.latest_security_policies
        result = []
        for elb in elbv2:
            response = self.aws_elbsv2_client.describe_listeners(LoadBalancerArn=elb['LoadBalancerArn'])
            listeners = response['Listeners']
            elb_arn = elb['LoadBalancerArn']
            elb_type = elb['Type']

            if elb_type == 'application' or elb_type == 'network':
                secure_listeners = 0
                for listener in listeners:
                    ssl_policy = listener.get('SslPolicy')
                    if ssl_policy in latest_security_policies:
                        secure_listeners += 1
                
                if secure_listeners == len(listeners):
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": elb_arn,
                        "item_type": "aws_elbv2",
                        "test_name": test_name,
                        "test_result": "no_issue_found"
                    })
                else:
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "timestamp": time.time(),
                        "item": elb_arn,
                        "item_type": "aws_elbv2",
                        "test_name": test_name,
                        "test_result": "issue_found"
                    })
            else:
                # GWLB 
                result.append({
                    "user": self.user_id,
                    "account_arn": self.account_arn,
                    "account": self.account_id,
                    "timestamp": time.time(),
                    "item": elb_arn,
                    "item_type": "aws_elbv2",
                    "test_name": test_name,
                    "test_result": "no_issue_found"
                })
        return result
