import time
import boto3
import interfaces
import json


def _format_string_to_json(text):
    return json.loads(text)


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_vpc_client = boto3.client('ec2')
        self.cache = {}
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.all_vpc_details = self._get_all_vpc()
        self.all_ami_images = self._get_all_ami_images()

    def _get_all_vpc(self):
        response = self.aws_vpc_client.describe_vpcs()
        vpc_detail = []
        # If you have the required permissions, the error response is DryRunOperation .
        # Otherwise, it is UnauthorizedOperation .
        if response and 'Vpcs' in response and response['Vpcs']:
            vpc_detail.extend(response['Vpcs'])
        while 'NextToken' in response and response['NextToken']:
            response = self.aws_vpc_client.describe_vpcs(NextToken=response['NextToken'])
            if response and 'Vpcs' in response and response['Vpcs']:
                vpc_detail.extend(response['Vpcs'])
        return vpc_detail

    def _get_all_ami_images(self):
        response_of_describe_images = self.aws_vpc_client.describe_images()
        if response_of_describe_images and 'Images' in response_of_describe_images and response_of_describe_images[
            'Images']:
            return response_of_describe_images['Images']
        return []

    def declare_tested_service(self) -> str:
        return 'vpc'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        return self.detect_vpc_logging_status() + \
               self.detect_vpc_endpoint_publicly_accessibility() + \
               self.detect_network_acl_restriction_status() + \
               self.detect_vpc_network_acl_inbound_and_outbound_traffic_rules() + \
               self.detect_default_nacl_used() + \
               self.detect_vpc_dnc_resolution_enabled() + \
               self.detect_vpc_unrestricted_icmp_access() + \
               self.detect_securitygroup_inbound_rule_without_specified_protocol() + \
               self.detect_public_and_not_encrypted_ami_images() + \
               self.detect_vpc_peering_connection() + \
               self.detect_unrestricted_ssh_access() + \
               self.detect_vpc_unrestricted_smb_access() + \
               self.detect_vpc_unrestricted_dns_tcp_access() + \
               self.detect_vpc_unrestricted_vnc_server_access() + \
               self.detect_vpc_unrestricted_dns_udp_access() + \
               self.detect_vpc_unrestricted_ftp_access() + \
               self.detect_vpc_unrestricted_cifs_access() + \
               self.detect_vpc_default_security_groups_in_use() + \
               self.detect_vpc_unrestricted_telnet_access() + \
               self.detect_vpc_unrestricted_rdp_access() + \
               self.detect_vpc_unrestricted_ftp_data_access() + \
               self.detect_vpc_unrestricted_smtp_access() + \
               self.detect_vpc_unrestricted_sql_server_tcp_access() + \
               self.detect_vpc_unrestricted_sql_server_udp_access() + \
               self.detect_vpc_unrestricted_net_bios_access() + \
               self.detect_vpc_unrestricted_mysql_access() + \
               self.detect_vpc_unrestricted_postgre_sql_access() + \
               self.detect_vpc_unrestricted_vnc_listener_access() + \
               self.detect_vpc_eip_in_use() + \
               self.detect_vpc_security_group_per_vpc_limit()

    def _append_vpc_test_result(self, vpc_detail, test_name, issue_status):
        return {
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": vpc_detail['VpcId'],
            "item_type": "vpc",
            "test_name": test_name,
            "test_result": issue_status
        }

    def _append_vpc_acm_test_result(self, acm_image_id, test_name, issue_status):
        return {
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": acm_image_id,
            "item_type": "vpc",
            "test_name": test_name,
            "test_result": issue_status
        }

    def _check_logging_status(self, test_name, ):
        logging_result = []
        for vpc_detail in self.all_vpc_details:
            result = self.aws_vpc_client.describe_flow_logs(Filters=[
                {
                    'Name': 'resource-id',
                    'Values': [vpc_detail['VpcId']]
                },
            ])
            if result and result['FlowLogs']:
                logging_result.append(self._append_vpc_test_result(vpc_detail, test_name, 'no_issue_found'))
            else:
                logging_result.append(self._append_vpc_test_result(vpc_detail, test_name, 'issue_found'))
        return logging_result

    def _check_vpc_public_accessibility(self, test_name):
        vpc_public_accessible = []
        for vpc_detail in self.all_vpc_details:
            result = self.aws_vpc_client.describe_vpc_endpoints(Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_detail['VpcId']]
                },
            ])
            if result and 'VpcEndpoints' in result and result['VpcEndpoints']:
                for vpc_end_point_data in result['VpcEndpoints']:
                    if 'PolicyDocument' in vpc_end_point_data and vpc_end_point_data['PolicyDocument']:
                        policy_document_json_data = _format_string_to_json(vpc_end_point_data['PolicyDocument'])
                        if 'Statement' in policy_document_json_data:
                            issue_found = False
                            for statement_dict in policy_document_json_data['Statement']:
                                if 'Principal' in statement_dict and statement_dict[
                                    'Principal'] == '*' or 'Principal' in statement_dict and 'AWS' in statement_dict[
                                    'Principal'] and statement_dict['Principal']['AWS'] == '*':
                                    issue_found = True
                                    break
                            if issue_found:
                                vpc_public_accessible.append(
                                    self._append_vpc_test_result(vpc_detail, test_name, 'issue_found'))
                            else:
                                vpc_public_accessible.append(
                                    self._append_vpc_test_result(vpc_detail, test_name, 'no_issue_found'))
            else:
                vpc_public_accessible.append(
                    self._append_vpc_test_result(vpc_detail, test_name, 'no_issue_found'))
        return vpc_public_accessible

    def _check_ingress_administration_ports_range_for_network_acls_inbound_rule(self, test_name):
        ingress_traffic_test_result = []
        for vpc_detail in self.all_vpc_details:
            vpc_id = vpc_detail['VpcId']
            response = self.aws_vpc_client.describe_network_acls(Filters=[{
                'Name': 'vpc-id',
                'Values': [vpc_id]
            }, ])
            if response and 'NetworkAcls' in response and len(response['NetworkAcls']):
                for acl in response['NetworkAcls']:
                    issue_found = False
                    for network_acl_rules in acl['Entries']:
                        if 'Egress' in network_acl_rules and not network_acl_rules['Egress'] and network_acl_rules[
                            'RuleAction'].lower() == 'allow':
                            if 'PortRange' not in network_acl_rules:
                                issue_found = True
                                break
                            # elif 'PortRange' in network_acl_rules and network_acl_rules['PortRange'] == []:
                    if issue_found:
                        ingress_traffic_test_result.append(
                            self._append_vpc_test_result(vpc_detail, test_name, 'issue_found'))
                    else:
                        ingress_traffic_test_result.append(
                            self._append_vpc_test_result(vpc_detail, test_name, 'no_issue_found'))
            else:
                ingress_traffic_test_result.append(
                    self._append_vpc_test_result(vpc_detail, test_name, 'no_issue_found'))
        return ingress_traffic_test_result

    def _check_securitygroup_inbound_rule_without_specified_protocol(self, test_name):
        security_groups_inbound_rule_result = []
        for vpc_detail in self.all_vpc_details:
            security_groups_response = self.aws_vpc_client.describe_security_groups(Filters=[{
                'Name': 'vpc-id',
                'Values': [vpc_detail['VpcId']]
            }])
            issue_found = False
            if security_groups_response and 'SecurityGroups' in security_groups_response and security_groups_response[
                'SecurityGroups']:
                for security_groups_dict in security_groups_response['SecurityGroups']:
                    if issue_found:
                        break
                    if 'IpPermissions' in security_groups_dict and security_groups_dict['IpPermissions']:
                        for ip_permission_dict in security_groups_dict['IpPermissions']:
                            if 'IpProtocol' in ip_permission_dict and str(
                                    ip_permission_dict['IpProtocol']) == '-1' or str(
                                ip_permission_dict['IpProtocol']).lower() == 'all':
                                issue_found = True
                                break
                    else:
                        issue_found = True
                        break


            else:
                issue_found = True
            if issue_found:
                security_groups_inbound_rule_result.append(
                    self._append_vpc_test_result(vpc_detail, test_name, 'issue_found'))
            else:
                security_groups_inbound_rule_result.append(
                    self._append_vpc_test_result(vpc_detail, test_name, 'no_issue_found'))
        return security_groups_inbound_rule_result

    def _check_default_nacl_used(self, test_name):
        default_nacl_used_result = []
        for vpc_detail in self.all_vpc_details:
            network_acls_response = self.aws_vpc_client.describe_network_acls(Filters=[{
                'Name': 'vpc-id',
                'Values': [vpc_detail['VpcId']]
            }])
            issue_found = False
            if 'NetworkAcls' in network_acls_response and network_acls_response['NetworkAcls']:
                for network_acls_dict in network_acls_response['NetworkAcls']:
                    if 'IsDefault' in network_acls_dict and network_acls_dict['IsDefault']:
                        issue_found = True
                        break
            else:
                issue_found = True

            if issue_found:
                default_nacl_used_result.append(self._append_vpc_test_result(vpc_detail, test_name, 'issue_found'))
            else:
                default_nacl_used_result.append(self._append_vpc_test_result(vpc_detail, test_name, 'no_issue_found'))

        return default_nacl_used_result

    def _check_vpc_dns_resolution_enabled(self, test_name):
        vpc_dns_resolution_result = []
        for vpc_detail in self.all_vpc_details:
            dns_support_response = self.aws_vpc_client.describe_vpc_attribute(
                Attribute='enableDnsSupport',
                VpcId=vpc_detail['VpcId']
            )
            if 'EnableDnsSupport' in dns_support_response and dns_support_response['EnableDnsSupport'] and 'Value' in \
                    dns_support_response['EnableDnsSupport'] and dns_support_response['EnableDnsSupport']['Value']:
                vpc_dns_resolution_result.append(self._append_vpc_test_result(vpc_detail, test_name, 'no_issue_found'))
            else:
                vpc_dns_resolution_result.append(self._append_vpc_test_result(vpc_detail, test_name, 'issue_found'))

        return vpc_dns_resolution_result

    def _check_vpc_unrestricted_icmp_access(self, test_name):
        vpc_unrestricted_icmp_access = []
        for vpc_detail in self.all_vpc_details:
            issue_found = False
            security_groups_response = self.aws_vpc_client.describe_security_groups(Filters=[{
                'Name': 'vpc-id',
                'Values': [vpc_detail['VpcId']]
            }, {
                'Name': 'ip-permission.protocol',
                'Values': ['icmp']

            }, {
                'Name': 'ip-permission.cidr',
                'Values': ['0.0.0.0/0']
            }
                , {
                    'Name': 'ip-permission.ipv6-cidr',
                    'Values': ['::/0']
                }])
            if security_groups_response and 'SecurityGroups' in security_groups_response and security_groups_response[
                'SecurityGroups']:
                for security_groups_response_dict in security_groups_response['SecurityGroups']:
                    if 'IpPermissions' in security_groups_response_dict and security_groups_response_dict[
                        'IpPermissions']:
                        issue_found = True
                        break
            if issue_found:
                vpc_unrestricted_icmp_access.append(self._append_vpc_test_result(vpc_detail, test_name, 'issue_found'))
            else:
                vpc_unrestricted_icmp_access.append(
                    self._append_vpc_test_result(vpc_detail, test_name, 'no_issue_found'))

        return vpc_unrestricted_icmp_access

    def _check_inbound_traffic(self, ):
        inbound_traffic_result = []
        for vpc_detail in self.all_vpc_details:
            vpc_id = vpc_detail['VpcId']
            response = self.aws_vpc_client.describe_network_acls(Filters=[{
                'Name': 'vpc-id',
                'Values': [vpc_id]
            }, ])
            inoutbound_allow_rule_number = []
            inoutbound_deny_rule_number = []
            inoutbound_allow_rule_asterisk = ''
            if response and 'NetworkAcls' in response:
                issue_found = False
                for network_acl_rules_dict in response['NetworkAcls']:
                    if issue_found:
                        break
                    for network_acl_rules in network_acl_rules_dict['Entries']:
                        if 'Egress' in network_acl_rules and not network_acl_rules['Egress'] and network_acl_rules[
                            'CidrBlock'] == '0.0.0.0/0':
                            if network_acl_rules[
                                'RuleAction'].lower() == 'allow':
                                if str(network_acl_rules['RuleNumber']) == '*':
                                    inoutbound_allow_rule_asterisk = '*'
                                else:
                                    inoutbound_allow_rule_number.append(network_acl_rules['RuleNumber'])
                            else:
                                inoutbound_deny_rule_number.append(network_acl_rules['RuleNumber'])
                    inoutbound_allow_rule_number.sort()
                    inoutbound_deny_rule_number.sort()
                    if len(inoutbound_allow_rule_number) and len(
                            inoutbound_deny_rule_number) and inoutbound_allow_rule_number[0] <= \
                            inoutbound_deny_rule_number[
                                0] or inoutbound_allow_rule_asterisk == '*':
                        issue_found = True

                if issue_found:
                    inbound_traffic_result.append(
                        self._append_vpc_test_result(vpc_detail, 'network_acl_inbound_traffic_is_restricted',
                                                     'issue_found'))
                else:
                    inbound_traffic_result.append(
                        self._append_vpc_test_result(vpc_detail, 'network_acl_inbound_traffic_is_restricted',
                                                     'no_issue_found'))

        return inbound_traffic_result

    def _check_outbound_traffic(self):
        outbound_traffic_result = []
        for vpc_detail in self.all_vpc_details:
            vpc_id = vpc_detail['VpcId']
            response = self.aws_vpc_client.describe_network_acls(Filters=[{
                'Name': 'vpc-id',
                'Values': [vpc_id]
            }, ])
            outbound_allow_rule_number = []
            outbound_deny_rule_number = []
            outbound_allow_rule_asterisk = ''
            if response and 'NetworkAcls' in response:
                issue_found = False
                for network_acl_rules_dict in response['NetworkAcls']:
                    if issue_found:
                        break
                    for network_acl_rules in network_acl_rules_dict['Entries']:
                        if 'Egress' in network_acl_rules and network_acl_rules['Egress'] and network_acl_rules[
                            'CidrBlock'] == '0.0.0.0/0':
                            if network_acl_rules[
                                'RuleAction'].lower() == 'allow':
                                if str(network_acl_rules['RuleNumber']) == '*':
                                    outbound_allow_rule_asterisk = '*'
                                else:
                                    outbound_allow_rule_number.append(network_acl_rules['RuleNumber'])
                            else:
                                outbound_deny_rule_number.append(network_acl_rules['RuleNumber'])
                    outbound_allow_rule_number.sort()
                    outbound_deny_rule_number.sort()
                    if len(outbound_allow_rule_number) and len(
                            outbound_deny_rule_number) and outbound_allow_rule_number[0] <= outbound_deny_rule_number[
                        0] or outbound_allow_rule_asterisk == '*':
                        issue_found = True
                if issue_found:
                    outbound_traffic_result.append(
                        self._append_vpc_test_result(vpc_detail, 'network_acl_outbound_traffic_is_restricted',
                                                     'issue_found'))

                else:
                    outbound_traffic_result.append(
                        self._append_vpc_test_result(vpc_detail, 'network_acl_outbound_traffic_is_restricted',
                                                     'no_issue_found'))
        return outbound_traffic_result

    def _all_check_unrestricted_ssh_access(self, response):
        issue_list = []
        if 'SecurityGroups' in response and response['SecurityGroups']:
            for security_group_dict in response['SecurityGroups']:
                for ip_permission_dict in security_group_dict['IpPermissions']:
                    if ip_permission_dict['IpProtocol'] in ['tcp', '6', '-1'] and (
                            ('FromPort' in ip_permission_dict and ip_permission_dict[
                                'FromPort'] <= 22 and 'ToPort' in ip_permission_dict and ip_permission_dict[
                                 'ToPort'] >= 22) or (
                                    str('FromPort' in ip_permission_dict and ip_permission_dict[
                                        'FromPort']) == '-1' and str(
                                'ToPort' in ip_permission_dict and ip_permission_dict['ToPort']) == '-1')):
                        issue_list.append(security_group_dict['GroupId'])
                        break
        return issue_list

    def _find_all_vpc_unrestricted_protocol_access(self, response, port_number_list, protocol_list):
        issue_list = []
        if 'SecurityGroups' in response and response['SecurityGroups']:
            for security_group_dict in response['SecurityGroups']:
                for ip_permission_dict in security_group_dict['IpPermissions']:
                    for port_number in port_number_list:
                        if ip_permission_dict['IpProtocol'] in protocol_list and (
                                ('FromPort' in ip_permission_dict and ip_permission_dict[
                                    'FromPort'] <= port_number and 'ToPort' in ip_permission_dict and
                                 ip_permission_dict[
                                     'ToPort'] >= port_number) or (
                                        str('FromPort' in ip_permission_dict and ip_permission_dict[
                                            'FromPort']) == '-1' and str(
                                    'ToPort' in ip_permission_dict and ip_permission_dict['ToPort']) == '-1')):
                            issue_list.append(security_group_dict['GroupId'])
                    if issue_list:
                        break
        return issue_list

    def _find_security_group_response(self, port_number, protocol_list, test_name):
        result = []
        for vpc_detail in self.all_vpc_details:
            ipv4_response = self.aws_vpc_client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_detail['VpcId']]
                    },
                    {'Name': "ip-permission.cidr", "Values": ['0.0.0.0/0']}

                ])
            issue_list = self._find_all_vpc_unrestricted_protocol_access(ipv4_response, port_number, protocol_list)
            ipv6_response = self.aws_vpc_client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_detail['VpcId']]
                    },
                    {'Name': 'ip-permission.ipv6-cidr', 'Values': ['::/0']}

                ])
            issue_list.extend(
                self._find_all_vpc_unrestricted_protocol_access(ipv6_response, port_number, protocol_list))
            issue_found = list(dict.fromkeys(issue_list))
            if issue_found:
                vpc_id = vpc_detail['VpcId']
                for data in issue_found:
                    vpc_detail['VpcId'] = vpc_id + '@@' + data
                    result.append(
                        self._append_vpc_test_result(vpc_detail, test_name, 'issue_found'))
                vpc_detail['VpcId'] = vpc_id
            else:
                result.append(
                    self._append_vpc_test_result(vpc_detail, test_name, 'no_issue_found'))
        return result

    def _append_epi_test_result(self, eip_detail, test_name, issue_status):
        return {
            "user": self.user_id,
            "account_arn": self.account_arn,
            "account": self.account_id,
            "timestamp": time.time(),
            "item": eip_detail['AllocationId'],
            "item_type": "vpc_elastic_ip",
            "test_name": test_name,
            "test_result": issue_status
        }

    def detect_vpc_logging_status(self) -> list:
        return self._check_logging_status('vpc_flow_logging_is_enabled_in_all_vpcs')

    def detect_vpc_endpoint_publicly_accessibility(self):
        return self._check_vpc_public_accessibility('vpc_endpoint_publicly_accessible')

    def detect_vpc_network_acl_inbound_and_outbound_traffic_rules(self):
        return self._check_outbound_traffic() + self._check_inbound_traffic()

    def detect_network_acl_restriction_status(self):
        return self._check_ingress_administration_ports_range_for_network_acls_inbound_rule(
            'network_acl_do_not_allow_ingress_from_0.0.0.0/0_to_remote_server_administration_ports')

    def detect_securitygroup_inbound_rule_without_specified_protocol(self):
        return self._check_securitygroup_inbound_rule_without_specified_protocol(
            'vpc_securitygroup_inbound_rule_without_specified_protocol')

    def detect_default_nacl_used(self):
        return self._check_default_nacl_used('vpc_default_nacl_used')

    def detect_vpc_dnc_resolution_enabled(self):
        return self._check_vpc_dns_resolution_enabled('vpc_default_nacl_used')

    def detect_vpc_unrestricted_icmp_access(self):
        return self._check_vpc_unrestricted_icmp_access('vpc_unrestricted_icmp_access')

    def detect_public_and_not_encrypted_ami_images(self):
        public_ami_result = []
        encrypted_ami_result = []
        for ami_images_dict in self.all_ami_images:
            issue_found_on_public_acm = False
            issue_found_on_encrypted_acm = False
            if 'Public' in ami_images_dict and ami_images_dict['Public']:
                issue_found_on_public_acm = True
            if 'BlockDeviceMappings' in ami_images_dict and ami_images_dict['BlockDeviceMappings']:
                for blocked_device_dict in ami_images_dict['BlockDeviceMappings']:
                    if 'Ebs' in blocked_device_dict and blocked_device_dict['Ebs'] and 'Encrypted' in \
                            blocked_device_dict['Ebs'] and blocked_device_dict['Ebs']['Encrypted']:
                        issue_found_on_encrypted_acm = True
                        break
            else:
                issue_found_on_encrypted_acm = True
            if issue_found_on_public_acm:
                public_ami_result.append(
                    self._append_vpc_acm_test_result(ami_images_dict['ImageId'], 'public_ami_detected', 'issue_found'))
            else:
                public_ami_result.append(
                    self._append_vpc_acm_test_result(ami_images_dict['ImageId'], 'public_ami_detected',
                                                     'no_issue_found'))
            if issue_found_on_encrypted_acm:
                encrypted_ami_result.append(self._append_vpc_acm_test_result(ami_images_dict['ImageId'],
                                                                             'source_ami_snapshot_is_not_encrypted',
                                                                             'issue_found'))
            else:
                encrypted_ami_result.append(self._append_vpc_acm_test_result(ami_images_dict['ImageId'],
                                                                             'source_ami_snapshot_is_not_encrypted',
                                                                             'no_issue_found'))
        return public_ami_result + encrypted_ami_result

    def detect_unrestricted_ssh_access(self):
        unrestricted_ssh_access_result = []
        for vpc_detail in self.all_vpc_details:
            vpc_id = vpc_detail['VpcId']
            response = self.aws_vpc_client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    },
                    {'Name': "ip-permission.cidr", "Values": ['0.0.0.0/0']}

                ]
            )
            issue_found = self._all_check_unrestricted_ssh_access(response)
            ipv6_response = self.aws_vpc_client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    },
                    {'Name': 'ip-permission.ipv6-cidr', 'Values': ['::/0']}
                ])
            issue_found.extend(self._all_check_unrestricted_ssh_access(ipv6_response))
            issue_found = list(dict.fromkeys(issue_found))
            if issue_found:
                vpc_id = vpc_detail['VpcId']
                for data in issue_found:
                    vpc_detail['VpcId'] = vpc_id + '@@' + data
                    unrestricted_ssh_access_result.append(
                        self._append_vpc_test_result(vpc_detail, 'unrestricted_ssh_access', 'issue_found'))
            else:
                unrestricted_ssh_access_result.append(
                    self._append_vpc_test_result(vpc_detail, 'unrestricted_ssh_access', 'no_issue_found'))
        return unrestricted_ssh_access_result

    def detect_vpc_peering_connection(self):
        vpc_peering_connection_status = []
        for vpc_detail in self.all_vpc_details:
            issue_found = []
            vpc_peering_connection_response = self.aws_vpc_client.describe_vpc_peering_connections(Filters=[
                {
                    'Name': 'requester-vpc-info.vpc-id',
                    'Values': [vpc_detail['VpcId']]
                }
            ])
            if vpc_peering_connection_response and 'VpcPeeringConnections' in vpc_peering_connection_response and \
                    vpc_peering_connection_response['VpcPeeringConnections']:
                for vpc_peering_connection_dict in vpc_peering_connection_response['VpcPeeringConnections']:
                    if vpc_peering_connection_dict['AccepterVpcInfo']['OwnerId'] != \
                            vpc_peering_connection_dict['RequesterVpcInfo']['OwnerId']:
                        issue_found.append(vpc_peering_connection_dict['VpcPeeringConnectionId'])

            if issue_found:
                vpc_id = vpc_detail['VpcId']
                for data in issue_found:
                    vpc_detail['VpcId'] = vpc_id + '@@' + data
                    vpc_peering_connection_status.append(
                        self._append_vpc_test_result(vpc_detail, 'unauthorized_vpc_peering', 'issue_found'))
            else:
                vpc_peering_connection_status.append(
                    self._append_vpc_test_result(vpc_detail, 'unauthorized_vpc_peering', 'no_issue_found'))
        return vpc_peering_connection_status

    def detect_vpc_unrestricted_smb_access(self):
        return self._find_security_group_response([445], ['tcp', '6', '-1'], 'vpc_unrestricted_smb_access')

    def detect_vpc_unrestricted_dns_tcp_access(self):
        return self._find_security_group_response([53], ['tcp', '6', '-1'], 'vpc_unrestricted_dns_tcp_access')

    def detect_vpc_unrestricted_vnc_server_access(self):
        return self._find_security_group_response([5800, 5900], ['tcp', '6', '-1'],
                                                  'vpc_unrestricted_vnc_server_access')

    def detect_vpc_unrestricted_dns_udp_access(self):
        return self._find_security_group_response([53], ['udp', '17', '-1'], 'vpc_unrestricted_dns_udp_access')

    def detect_vpc_unrestricted_ftp_access(self):
        return self._find_security_group_response([21], ['tcp', '6', '-1'], 'vpc_unrestricted_ftp_access')

    def detect_vpc_unrestricted_cifs_access(self):
        return self._find_security_group_response([445], ['udp', '17', '-1'], 'vpc_unrestricted_cifs_access')

    def detect_vpc_default_security_groups_in_use(self):
        result = []
        test_name = 'vpc_default_security_groups_in_use'
        all_ec2_instance = []
        ec2_response = self.aws_vpc_client.describe_instances()
        if ec2_response and 'Reservations' in ec2_response and ec2_response['Reservations']:
            for reservations_dict in ec2_response['Reservations']:
                if 'Instances' in reservations_dict and reservations_dict['Instances']:
                    all_ec2_instance.extend(reservations_dict['Instances'])
        for ec2_instance_dict in all_ec2_instance:
            response = self.aws_vpc_client.describe_security_groups(
                Filters=[
                    {
                        'Name': 'group-id',
                        'Values': [security_group_dict['GroupId'] for security_group_dict in
                                   ec2_instance_dict['SecurityGroups']]
                    }
                ])
            if 'SecurityGroups' in response and response['SecurityGroups']:
                for security_groups_dict in response['SecurityGroups']:
                    if 'GroupName' in security_groups_dict and security_groups_dict['GroupName'] == 'default':
                        ec2_instance_dict['VpcId'] = security_groups_dict['VpcId'] + '@@' + security_groups_dict[
                            'GroupId']
                        result.append(self._append_vpc_test_result(ec2_instance_dict, test_name, 'issue_found'))
                        ec2_instance_dict['VpcId'] = security_groups_dict['VpcId']
                    else:
                        result.append(self._append_vpc_test_result(ec2_instance_dict, test_name, 'no_issue_found'))
        return result

    def detect_vpc_unrestricted_telnet_access(self):
        return self._find_security_group_response([23], ['tcp', '6', '-1'], 'vpc_unrestricted_telnet_access')

    def detect_vpc_unrestricted_rdp_access(self):
        return self._find_security_group_response([3389], ['tcp', '6', '-1'], 'vpc_unrestricted_rdp_access')

    def detect_vpc_unrestricted_ftp_data_access(self):
        return self._find_security_group_response([20], ['tcp', '6', '-1'], 'vpc_unrestricted_rdp_access')

    def detect_vpc_unrestricted_smtp_access(self):
        return self._find_security_group_response([25], ['tcp', '6', '-1'], 'vpc_unrestricted_smtp_access')

    def detect_vpc_unrestricted_sql_server_tcp_access(self):
        return self._find_security_group_response([1433], ['tcp', '6', '-1'], 'vpc_unrestricted_sql_server_tcp_access')

    def detect_vpc_unrestricted_sql_server_udp_access(self):
        return self._find_security_group_response([1433], ['udp', '17', '-1'], 'vpc_unrestricted_sql_server_udp_access')

    def detect_vpc_unrestricted_net_bios_access(self):
        return self._find_security_group_response([137, 138], ['udp', '17', '-1'], 'vpc_unrestricted_net_bios_access')

    def detect_vpc_unrestricted_mysql_access(self):
        return self._find_security_group_response([4333], ['tcp', '6', '-1'], 'vpc_unrestricted_mysql_access')

    def detect_vpc_unrestricted_postgre_sql_access(self):
        return self._find_security_group_response([5432], ['tcp', '6', '-1'], 'vpc_unrestricted_postgre_sql_access')

    def detect_vpc_unrestricted_vnc_listener_access(self):
        return self._find_security_group_response([5500], ['tcp', '6', '-1'], 'vpc_unrestricted_vnc_listener_access')

    def detect_vpc_eip_in_use(self):
        result = []
        test_name = 'vpc_ip_address_is_attached_to_a_host_or_eni'
        response = self.aws_vpc_client.describe_addresses()
        for address_dict in response['Addresses']:
            if 'AssociationId' not in address_dict or (
                    'AssociationId' in address_dict and not address_dict['AssociationId']):
                result.append(self._append_epi_test_result(address_dict, test_name, 'issue_found'))
            else:
                result.append(self._append_epi_test_result(address_dict, test_name, 'no_issue_found'))
        return result

    def detect_vpc_security_group_per_vpc_limit(self):
        result = []
        test_name = 'detect_vp_security_group_per_vpc_limit'
        for vpc_detail in self.all_vpc_details:
            security_groups_response = self.aws_vpc_client.describe_security_groups(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_detail['VpcId']]}], MaxResults=451)
            count = len(security_groups_response['SecurityGroups'])
            if count >= 450:
                result.append(self._append_vpc_test_result(vpc_detail, test_name, 'issue_found'))
            else:
                result.append(self._append_vpc_test_result(vpc_detail, test_name, 'no_issue_found'))
        return result

