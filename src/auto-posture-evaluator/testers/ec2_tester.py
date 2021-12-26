import time
from typing import Dict, List, Set
import boto3
import botocore.exceptions
import interfaces

class Tester(interfaces.TesterInterface):
    def __init__(self) -> None:
        self.aws_ec2_client = boto3.client('ec2')
        self.aws_ec2_resource = boto3.resource('ec2')
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.security_groups = self.aws_ec2_resource.security_groups.all()
        self.vpcs = self.aws_ec2_client.describe_vpcs()['Vpcs']
        self.set_security_group = self._get_all_security_group_ids(self.security_groups)

    def declare_tested_service(self) -> str:
        return 'ec2'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        all_inbound_permissions = self._get_all_inbound_permissions_by_security_groups(self.security_groups)
        all_outbound_permissions = self._get_all_outbound_permissions_by_security_groups(self.security_groups)

        return \
            self.get_inbound_http_access(all_inbound_permissions) + \
            self.get_inbound_https_access(all_inbound_permissions) + \
            self.get_inbound_mongodb_access(all_inbound_permissions) + \
            self.get_inbound_mysql_access(all_inbound_permissions) + \
            self.get_inbound_mssql_access(all_inbound_permissions) + \
            self.get_inbound_ssh_access(all_inbound_permissions) + \
            self.get_inbound_rdp_access(all_inbound_permissions) + \
            self.get_inbound_dns_access(all_inbound_permissions) + \
            self.get_inbound_telnet_access(all_inbound_permissions) + \
            self.get_inbound_rpc_access(all_inbound_permissions) + \
            self.get_inbound_icmp_access(all_inbound_permissions) + \
            self.get_security_group_allows_ingress_from_anywhere(all_inbound_permissions) + \
            self.get_vpc_default_security_group_restrict_traffic() + \
            self.get_outbound_access_to_all_ports(all_outbound_permissions) + \
            self.get_inbound_oracle_access(all_inbound_permissions) + \
            self.get_inbound_ftp_access(all_inbound_permissions) + \
            self.get_inbound_smtp_access(all_inbound_permissions) + \
            self.get_inbound_elasticsearch_access(all_inbound_permissions) + \
            self.get_inbound_tcp_netbios_access(all_inbound_permissions) + \
            self.get_inbound_udp_netbios(all_inbound_permissions) + \
            self.get_inbound_cifs_access(all_inbound_permissions)
            
    def _get_all_security_group_ids(self, instances) -> Set:
        return set(list(map(lambda i: i.id, list(instances))))

    def _get_all_inbound_permissions(self, instances):
        all_inbound_permissions = []
        for instance in instances:
            security_groups = instance.security_groups
            for security_group in security_groups:
                inbound_permissions = self.aws_ec2_resource.SecurityGroup(security_group['GroupId']).ip_permissions
                for i in inbound_permissions:
                    i['instance'] = instance
                    i['security_group'] = security_group
                    all_inbound_permissions.append(i)
        return all_inbound_permissions

    def _get_all_inbound_permissions_by_security_groups(self, security_groups) -> List[Dict]:
        inbound_rules = []
        for security_group in security_groups:
            rules = security_group.ip_permissions
            for rule in rules:
                rule['security_group'] = security_group
                inbound_rules.append(rule)
        return inbound_rules
    
    def _get_all_outbound_permissions_by_security_groups(self, security_groups) -> List[Dict]:
        outbound_rules = []
        for security_group in security_groups:
            rules = security_group.ip_permissions_egress
            for rule in rules:
                rule['security_group'] = security_group
                outbound_rules.append(rule)
        return outbound_rules

    def _get_inbound_port_access(self, all_inbound_permissions, target_port, test_name, protocol="tcp") -> List[Dict]:
        result = []
        instances = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == "-1") or ((permission['FromPort'] <= target_port and permission['ToPort'] >= target_port) and permission['IpProtocol'] == protocol), all_inbound_permissions))))
        instances_with_issue = set(instances)
        instances_with_no_issue = self.set_security_group.difference(instances_with_issue)

        for i in instances_with_issue:
            result.append({
               "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "issue_found"
                })
        
        for i in instances_with_no_issue:
            result.append({
               "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
        return result

    def get_inbound_http_access(self, all_inbound_permissions) -> List:
        test_name = "ec2_inbound_http_access_restricted"
        return self._get_inbound_port_access(all_inbound_permissions, 80, test_name)

    def get_inbound_https_access(self, all_inbound_permissions) -> List:
        test_name = "ec2_inbound_https_access_restricted"
        return self._get_inbound_port_access(all_inbound_permissions, 443, test_name)
    
    def get_inbound_mongodb_access(self, all_inbound_permissions) -> List:
        test_name = "ec2_inbound_mongodb_access_restricted"
        return self._get_inbound_port_access(all_inbound_permissions, 27017, test_name)
    
    def get_inbound_mysql_access(self, all_inbound_permissions) -> List:
        test_name = "ec2_inbound_mysql_access_restricted"
        return self._get_inbound_port_access(all_inbound_permissions, 3306, test_name)
    
    def get_inbound_mssql_access(self, all_inbound_permissions) -> List:
        test_name = "ec2_inbound_mssql_access_restricted"
        return self._get_inbound_port_access(all_inbound_permissions, 1433, test_name)

    def get_inbound_ssh_access(self, all_inbound_permissions) -> List:
        test_name = "ec2_inbound_ssh_access_restricted"
        return self._get_inbound_port_access(all_inbound_permissions, 22, test_name)

    def get_inbound_rdp_access(self, all_inbound_permissions) -> List:
        test_name = "ec2_inbound_rdp_access_restricted"
        return self._get_inbound_port_access(all_inbound_permissions, 3389, test_name)
    
    def get_inbound_postgresql_access(self, all_inbound_permissions) -> List:
        test_name = "ec2_inbound_postgresql_access_restricted"
        return self._get_inbound_port_access(all_inbound_permissions, 5432, test_name)

    def get_inbound_tcp_netbios_access(self, all_inbound_permissions):
        test_name = "ec2_inbound_tcp_netbios_access_restricted"
        result = []
        instances = []
        NAMERESPORT = 137
        SESSIONPORT = 139
        instancse_137 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= NAMERESPORT and permission['ToPort'] >= NAMERESPORT) and permission['IpProtocol'] == 'tcp'), all_inbound_permissions))))
        instances.extend(instancse_137)
        instancse_139 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= SESSIONPORT and permission['ToPort'] >= SESSIONPORT) and permission['IpProtocol'] == 'tcp'), all_inbound_permissions))))
        instances.extend(instancse_139)
        
        instances_with_issue = set(instances)
        instances_with_no_issue = self.set_security_group.difference(instances_with_issue)

        for i in instances_with_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "issue_found"
            })

        for i in instances_with_no_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
        
        return result

    def get_inbound_dns_access(self, all_inbound_permissions):
        test_name = "ec2_inbound_dns_access_restricted"
        result = []
        target_port = 53
        instances = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == "-1") or ((permission['FromPort'] <= target_port and permission['ToPort'] >= target_port) and (permission['IpProtocol'] == "tcp" or permission['IpProtocol'] == "udp")), all_inbound_permissions))))
        instances_with_issue = set(instances)
        instances_with_no_issue = self.set_security_group.difference(instances_with_issue)
        for i in instances_with_issue:
            result.append({
               "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "issue_found"
            })

        for i in instances_with_no_issue:    
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
        return result

    def get_inbound_telnet_access(self, all_inbound_permissions):
        test_name = "ec2_inbound_telnet_access_restricted"
        return self._get_inbound_port_access(all_inbound_permissions, 23, test_name)

    def get_inbound_cifs_access(self, all_inbound_permissions):
        test_name = "ec2_inbound_cifs_access_restricted"
        result = []
        instances = []
        PORT137 = 137
        PORT138 = 138
        PORT139 = 139
        PORT445 = 445
        PORT3020 = 3020
        
        instancse_137 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= PORT137 and permission['ToPort'] >= PORT137) and permission['IpProtocol'] == 'udp'), all_inbound_permissions))))
        instances.extend(instancse_137)
        instancse_138 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= PORT138 and permission['ToPort'] >= PORT138) and permission['IpProtocol'] == 'udp'), all_inbound_permissions))))
        instances.extend(instancse_138)
        instancse_139 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= PORT139 and permission['ToPort'] >= PORT139) and permission['IpProtocol'] == 'tcp'), all_inbound_permissions))))
        instances.extend(instancse_139)
        instancse_445 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= PORT445 and permission['ToPort'] >= PORT445) and permission['IpProtocol'] == 'tcp'), all_inbound_permissions))))
        instances.extend(instancse_445)
        instancse_3020 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= PORT3020 and permission['ToPort'] >= PORT3020) and permission['IpProtocol'] == 'tcp'), all_inbound_permissions))))
        instances.extend(instancse_3020)

        instances_with_issue = set(instances)
        instances_with_no_issue = self.set_security_group.difference(instances_with_issue)

        for i in instances_with_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "issue_found"
            })
        
        for i in instances_with_no_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
        
        return result
    
    def get_inbound_elasticsearch_access(self, all_inbound_permissions):
        test_name = "ec2_inbound_elasticsearch_access_restricted"
        results = []
        instances = []
        PORT9200 = 9200
        PORT9300 = 9300
        instances_9200 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= PORT9200 and permission['ToPort'] >= PORT9200) and permission['IpProtocol'] == 'tcp'), all_inbound_permissions))))
        instances.extend(instances_9200)
        instances_9300 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= PORT9300 and permission['ToPort'] >= PORT9300) and permission['IpProtocol'] == 'tcp'), all_inbound_permissions))))
        instances.extend(instances_9300)

        instances_with_issue = set(instances)
        instances_with_no_issue = self.set_security_group.difference(instances_with_issue)

        for i in instances_with_issue:
            results.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "issue_found"
            })
        
        for i in instances_with_no_issue:
            results.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
    
        return results
    
    def get_inbound_smtp_access(self, all_inbound_permissions):
        test_name = "ec2_inbound_smtp_access_restricted"
        result = []
        PORT25 = 25
        PORT587 = 587
        instances = []
        instances_25 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= PORT25 and permission['ToPort'] >= PORT25) and permission['IpProtocol'] == 'tcp'), all_inbound_permissions))))
        instances.extend(instances_25)
        instances_587 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= PORT587 and permission['ToPort'] >= PORT587) and permission['IpProtocol'] == 'tcp'), all_inbound_permissions))))
        instances.extend(instances_587)
        
        instances_with_issue = set(instances)
        instances_with_no_issue = self.set_security_group.difference(instances_with_issue)

        for i in instances_with_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "issue_found"
            })
        
        for i in instances_with_no_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
        
        return result

    def get_inbound_rpc_access(self, all_inbound_permissions):
        test_name = "ec2_inbound_rpc_access_restricted"
        return self._get_inbound_port_access(all_inbound_permissions, 135, test_name)

    def get_inbound_ftp_access(self, all_inbound_permissions):
        test_name = "ec2_inbound_ftp_access_restricted"
        result = []
        instances = []
        DATAPORT = 20
        COMMANDPORT = 21
        instances_20 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= DATAPORT and permission['ToPort'] >= DATAPORT) and permission['IpProtocol'] == 'tcp'), all_inbound_permissions))))
        instances.extend(instances_20)
        instances_21 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= COMMANDPORT and permission['ToPort'] >= COMMANDPORT) and permission['IpProtocol'] == 'tcp'), all_inbound_permissions))))
        instances.extend(instances_21)

        instances_with_issue = set(instances)
        instances_with_no_issue = self.set_security_group.difference(instances_with_issue)
        
        for i in instances_with_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "issue_found"
            })
        
        for i in instances_with_no_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
        
        return result

    def get_inbound_udp_netbios(self, all_inbound_permissions):
        test_name = "ec2_inbound_udp_netbios_access_restricted"
        result = []
        instances = []
        NAMERESPORT = 137
        DATAGRAMPORT = 138
        
        instancse_137 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= NAMERESPORT and permission['ToPort'] >= NAMERESPORT) and permission['IpProtocol'] == 'udp'), all_inbound_permissions))))
        instances.extend(instancse_137)
        instancse_138 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] == '-1') or ((permission['FromPort'] <= DATAGRAMPORT and permission['ToPort'] >= DATAGRAMPORT) and permission['IpProtocol'] == 'udp'), all_inbound_permissions))))
        instances.extend(instancse_138)
        
        instances_with_issue = set(instances)
        instances_with_no_issue = self.set_security_group.difference(instances_with_issue)

        for i in instances_with_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "issue_found"
            })
        
        for i in instances_with_no_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
        
        return result

    def get_outbound_access_to_all_ports(self, all_outbound_permissions):
        test_name = "ec2_outbound_access_to_all_ports_restricted"
        result = []
        security_groups = []

        for outbound_permission in all_outbound_permissions:
            if outbound_permission['IpProtocol'] == '-1':
                security_groups.append(outbound_permission['security_group'].id)
        
        security_groups_with_issues = set(security_groups)
        security_groups_with_no_issues = self.set_security_group.difference(security_groups_with_issues)
        for i in security_groups_with_issues:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "issue_found"
            })
        
        for i in security_groups_with_no_issues:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })

        return result 

    def get_vpc_default_security_group_restrict_traffic(self):
        test_name = "vpc_default_security_group_restrict_all_traffic"
        result = []
        
        all_vpcs = []
        for vpc in self.vpcs:
            all_vpcs.append(vpc['VpcId'])
        all_vpcs = set(all_vpcs)

        vpcs_with_issue = []
        security_groups = self.security_groups
        for security_group in security_groups:
            if security_group.group_name == "default":
                ingress_rules = security_group.ip_permissions
                egress_rules = security_group.ip_permissions_egress
                ingress_results = list(filter(lambda rule: (rule['IpProtocol'] == "-1") or (rule['FromPort'] >= 0 and rule['ToPort'] <= 65535), ingress_rules))
                egress_results = list(filter(lambda rule: (rule['IpProtocol'] == "-1") or (rule['FromPort'] >= 0 and rule['ToPort'] <= 65535), egress_rules))

                if len(ingress_results) != 0 or len(egress_results) != 0:
                    vpcs_with_issue.append(security_group.vpc_id)
        
        vpcs_with_issue = set(vpcs_with_issue)
        vpcs_with_no_issue = all_vpcs.difference(vpcs_with_issue)

        for vpc in vpcs_with_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": vpc,
                "item_type": "aws_vpc",
                "test_name": test_name,
                "test_result": "issue_found"
            })
        
        for vpc in vpcs_with_no_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": vpc,
                "item_type": "aws_vpc",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
        return result
    
    def get_inbound_oracle_access(self, all_inbound_permissions):
        test_name = "ec2_inbound_oracle_access_restricted"
        PORT1521 = 1521
        PORT2483 = 2483
        PORT2484 = 2484

        result = []
        instances = []

        instances_1521 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] =='-1') or (permission['FromPort'] <= PORT1521 and permission['ToPort'] >= PORT1521 and permission['IpProtocol'] == 'tcp'), all_inbound_permissions))))
        instances.extend(instances_1521)
        instances_2483 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] =='-1') or (permission['FromPort'] <= PORT2483 and permission['ToPort'] >= PORT2483), all_inbound_permissions))))
        instances.extend(instances_2483)
        instances_2484 = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: (permission['IpProtocol'] =='-1') or (permission['FromPort'] <= PORT2484 and permission['ToPort'] >= PORT2484), all_inbound_permissions))))
        instances.extend(instances_2484)

        instances_with_issue = set(instances)
        instances_with_no_issue = self.set_security_group.difference(instances_with_issue)

        for i in instances_with_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "issue_found"
            })

        for i in instances_with_no_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
        
        return result

    def get_inbound_icmp_access(self, all_inbound_permissions):
        test_name = "ec2_inbound_icmp_access_restricted"
        result = []
        instances = list(map(lambda i: i['security_group'].id, list(filter(lambda permission: permission['IpProtocol'] == "icmp" or permission['IpProtocol'] == "-1", all_inbound_permissions))))
        instances_with_issue = set(instances)
        instances_with_no_issue = self.set_security_group.difference(instances_with_issue)
        for i in instances_with_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "issue_found"
            })
        for i in instances_with_no_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": i,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })

        return result

    def get_security_group_allows_ingress_from_anywhere(self, all_inbound_permissions):
        test_name = "security_group_allows_ingress_to_remote_administration_ports_from_anywhere"
        result = []
        security_groups = []
        SSHPORT = 22
        RDPPORT = 3389
        for i in all_inbound_permissions:
            if i['IpProtocol'] == "-1" and len(i['IpRanges']) == 0:
                security_groups.append(i['security_group'].id)
            elif (i['FromPort'] <= SSHPORT and i['ToPort'] >= SSHPORT) or (i['FromPort'] <= RDPPORT and i['ToPort'] >= RDPPORT):
                for ip in i['IpRanges']:
                    if ip['CidrIp'] == '0.0.0.0/0':
                        security_groups.append(i['security_group'].id)
            else:
                continue
        security_groups_with_issue = set(security_groups)
        security_groups_with_no_issue = self.set_security_group.difference(security_groups_with_issue)

        for s in security_groups_with_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": s,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "issue_found"
            })
        
        for s in security_groups_with_no_issue:
            result.append({
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "timestamp": time.time(),
                "item": s,
                "item_type": "ec2_security_group",
                "test_name": test_name,
                "test_result": "no_issue_found"
            })
        return result