import time
import boto3
import re
import ipaddress
import botocore.exceptions
import interfaces


class Tester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_route53_client = boto3.client('route53')
        self.aws_ec2_client = boto3.client('ec2')
        self.hosted_zones = self.aws_route53_client.list_hosted_zones()
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')

    def declare_tested_service(self) -> str:
        return 'route53'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self) -> list:
        if self.hosted_zones is not None and 'HostedZones' in self.hosted_zones:
            return self.detect_dangling_dns_records()
        else:
            raise Exception("No Route53 data could be retrieved.")

    def detect_dangling_dns_records(self):
        result = []
        # Filtering the list to get the list of public zones only
        public_zones = [zone for zone in self.hosted_zones['HostedZones'] if not zone['Config']['PrivateZone']]
        for cur_zone in public_zones:
            # Get all records in this zone
            zone_records = self.aws_route53_client.list_resource_record_sets(
                HostedZoneId=cur_zone['Id'],
                StartRecordName='.',
                StartRecordType='A'
            )['ResourceRecordSets']

            # Extract record names
            record_names = [record_name["Name"] for record_name in zone_records]

            # Get public IPs per DNS record
            for record in zone_records:
                record_name = record["Name"]
                dangling_ip_addresses = []
                registered_addresses = [record["ResourceRecords"] for record in zone_records if record["Name"] == record_name][0]
                registered_ip_addresses = [resource_record["Value"] for resource_record in registered_addresses if re.match('\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}', str(resource_record["Value"]))]

                for registered_ip_address in registered_ip_addresses:
                    if ipaddress.ip_address(registered_ip_address).is_global:
                        try:
                            self.aws_ec2_client.describe_addresses(PublicIps=[registered_ip_address])
                        except botocore.exceptions.ClientError as ex:
                            if ex.response['Error']['Code'] == 'InvalidAddress.NotFound':
                                dangling_ip_addresses.append(registered_ip_address)
                            else:
                                raise ex

                if len(dangling_ip_addresses) > 0:
                    for dangling_ip_address in dangling_ip_addresses:
                        result.append({
                            "user": self.user_id,
                            "account_arn": self.account_arn,
                            "account": self.account_id,
                            "item": dangling_ip_address + "@@" + record_name,
                            "item_type": "dns_record",
                            "dns_record": record_name,
                            "record": record,
                            "test_name": 'aws_route53_dangling_dns_records',
                            "dangling_ip": dangling_ip_address,
                            "zone": cur_zone["Id"],
                            "timestamp": time.time(),
                            "test_result": "issue_found"
                        })
                else:
                    result.append({
                        "user": self.user_id,
                        "account_arn": self.account_arn,
                        "account": self.account_id,
                        "test_name": 'aws_route53_dangling_dns_records',
                        "item": record_name,
                        "item_type": "dns_record",
                        "record": record,
                        "timestamp": time.time(),
                        "test_result": "no_issue_found"
                    })

        return result
