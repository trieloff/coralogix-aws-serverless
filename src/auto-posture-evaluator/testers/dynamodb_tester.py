import time
import boto3
import interfaces


class DynamoDBTester(interfaces.TesterInterface):
    def __init__(self):
        self.aws_dynamodb_client = boto3.client('dynamodb')
        self.aws_dynamodb_resource = boto3.resource('dynamodb')
    def declare_required_args(self) -> list:
        return []

    def declare_tested_resource_type(self) -> str:
        return 'dynamodb'

    def declare_tested_service(self) -> str:
        return 'dynamodb'

    def declare_tested_provider(self) -> str:
        return 'aws'

    def run_tests(self, args_object) -> list:
        return \
        self.dynamodb_is_encrypted()

    def dynamodb_is_encrypted(self):
        result = []
        #Get All Trails Description
        table_list = self.aws_dynamodb_client.list_tables()
        #Get the Array and process each element
        for table_meta in table_list["TableNames"]:
            table = self.aws_dynamodb_resource.Table(name=table_meta)
            if table.sse_description == None:
                result.append({
                    "item" : table_meta,
                    "test_name" : 'dynamodb_is_encrypted',
                    "timestamp" : time.time()
                })
        if len(result) == 0:
            result.append({
            "test_name": 'dynamodb_is_encrypted',
            "item": None,
            "timestamp": time.time()                    
            })
        return result