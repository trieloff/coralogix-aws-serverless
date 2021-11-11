import datetime
import json
import os
import time
import boto3
import requests
import testers.route53_tester
import testers.s3_tester
import testers.cloudtrail_tester


class AutoPostureEvaluator:
    def __init__(self):
        if not os.environ.get('PRIVATE_KEY'):
            raise Exception("Missing the PRIVATE_KEY environment variable. CANNOT CONTINUE")

        self.coralogix_endpoint = os.environ.get('CORALOGIX_LOG_URL', 'api.coralogix.com')
        self.batch_size = int(os.environ.get('BATCH_SIZE', '10'))
        self.coralogix_headers = {'content-type': 'application/json'}
        self.coralogix_logs_object = {
            "privateKey": os.environ.get('PRIVATE_KEY'),
            "applicationName": os.environ.get('APPLICATION_NAME', 'NO_APP_NAME'),
            "subsystemName": os.environ.get('SUBSYSTEM_NAME', 'NO_SUB_NAME'),
            "computerName": "CoralogixServerlessLambda",
            "logEntries": []
        }
        self.regions = [
            "us-east-2",
            "us-east-1",
            "us-west-1",
            "us-west-2",
            "af-south-1",
            "ap-east-1",
            "ap-south-1",
            "ap-northeast-3",
            "ap-northeast-2",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-northeast-1",
            "ca-central-1",
            "eu-central-1",
            "eu-west-1",
            "eu-west-2",
            "eu-south-1",
            "eu-west-3",
            "eu-north-1",
            "me-south-1",
            "sa-east-1",
            "us-gov-east-1",
            "us-gov-west-1"
        ]
        self.user_id = boto3.client('sts').get_caller_identity().get('UserId')
        self.account_arn = boto3.client('sts').get_caller_identity().get('Arn')
        self.account_id = boto3.client('sts').get_caller_identity().get('Account')
        self.s3_buckets = boto3.client('s3').list_buckets()
        self.tests = [
            testers.s3_tester.S3Tester,
            testers.route53_tester.Route53Tester,
            testers.cloudtrail_tester.CloudtrailTester
        ]

    def run_tests(self):
        events_buffer = []
        test_id = datetime.datetime.now().isoformat()
        for tester in self.tests:
            cur_tester = tester()
            required_args = cur_tester.declare_required_args()
            args = {}
            if required_args and len(required_args) > 0:
                args_map = {
                    "s3_buckets": self.s3_buckets,
                    "regions": self.regions
                }
                for required_arg in required_args:
                    if required_arg in args_map:
                        args[required_arg] = args_map[required_arg]
                    else:
                        raise Exception("Unknown argument was requested (" + required_arg + ") by tester " + cur_tester.declare_tested_service() + ". CANNOT CONTINUE.")

            result = cur_tester.run_tests(args)
            error_template = "The result object from the tester " + cur_tester.declare_tested_service() + " does not match the required standard"
            if result is None:
                raise Exception(error_template + " (ResultIsNone). CANNOT CONTINUE.")
            if not isinstance(result, list):
                raise Exception(error_template + " (NotArray). CANNOT CONTINUE.")
            else:
                for result_obj in result:
                    if "timestamp" not in result_obj or "item" not in result_obj:
                        raise Exception(error_template + " (FieldsMissing). CANNOT CONTINUE.")
            test_types_reported = set([test_name["test_name"] for test_name in result])
            for test_type in test_types_reported:
                if len([test for test in result if test["test_name"] == test_type]) > 1 and \
                        len([result_obj for result_obj in result if result_obj["test_name"] == test_type and result_obj["item"] is None]) > 0:
                    raise Exception(error_template + " (ItemIsNoneButMoreThanSingleResultReturned). CANNOT CONTINUE.")

            log_message = {
                "event_type": "auto_posture_evaluator",
                "user": self.user_id,
                "account_arn": self.account_arn,
                "account": self.account_id,
                "resource_type": cur_tester.declare_tested_resource_type(),
                "service": cur_tester.declare_tested_service(),
                "provider": cur_tester.declare_tested_provider(),
                "test_id": test_id
            }
            for result_obj in result:
                cur_log_message = log_message.copy()
                cur_log_message["timestamp"] = result_obj["timestamp"] * 1000
                cur_log_message["event_sub_type"] = result_obj["test_name"]
                if result_obj["item"]:
                    cur_log_message["test_result"] = "issue_found"
                    cur_log_message["item"] = result_obj["item"]
                    for key in result_obj.keys():
                        if key not in cur_log_message:
                            cur_log_message[key] = result_obj[key]
                else:
                    cur_log_message["test_result"] = "no_issue_found"

                events_buffer.append({
                    "timestamp": cur_log_message["timestamp"],
                    "text": json.dumps({"security": cur_log_message}),
                    "severity": 1
                })
                if len(events_buffer) % self.batch_size == 0:
                    self.logger(events_buffer.copy())
                    events_buffer = []

        if len(events_buffer) > 0:
            self.logger(events_buffer.copy())

    def logger(self, log_messages):
        cur_logs_payload = self.coralogix_logs_object.copy()
        cur_logs_payload["logEntries"] = log_messages
        time_started = time.time()
        try:
            response = requests.post(
                url="https://" + self.coralogix_endpoint + "/api/v1/logs",
                headers=self.coralogix_headers,
                data=json.dumps(cur_logs_payload)
            )
            print("DEBUG: Sent " + str(len(log_messages)) + " events in " + str(time.time() - time_started) + "ms. Response status is " + str(response.status_code) + ", Response text: " + response.text)
            return response.text, cur_logs_payload
        except Exception as ex:
            print("ERROR: Failed to send " + str(len(log_messages)) + " events after " + str(time.time() - time_started) + "ms due to the following exception: " + str(ex))
