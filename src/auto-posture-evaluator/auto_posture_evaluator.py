import datetime
import json
import os
import time
import boto3
import requests
import importlib
import sys
testers_module_names = []
for module in os.listdir(os.path.dirname(__file__) + '/testers'):
    if module.startswith('_') or module[-3:] != '.py':
        continue
    module_name = "testers." + module[:-3]
    testers_module_names.append(module_name)
    importlib.import_module(module_name)
del module


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

        self.tests = []
        for tester_module in testers_module_names:
            if "Tester" in sys.modules[tester_module].__dict__:
                self.tests.append(sys.modules[tester_module].__dict__["Tester"])

    def run_tests(self):
        events_buffer = []
        test_id = datetime.datetime.now().isoformat()
        for tester in self.tests:
            cur_tester = tester()
            result = cur_tester.run_tests()
            error_template = "The result object from the tester " + cur_tester.declare_tested_service() + " does not match the required standard"
            if result is None:
                raise Exception(error_template + " (ResultIsNone). CANNOT CONTINUE.")
            if not isinstance(result, list):
                raise Exception(error_template + " (NotArray). CANNOT CONTINUE.")
            else:
                for result_obj in result:
                    if "timestamp" not in result_obj or "item" not in result_obj or "item_type" not in result_obj:
                        raise Exception(error_template + " (FieldsMissing). CANNOT CONTINUE.")
            test_types_reported = set([test_name["test_name"] for test_name in result])
            for test_type in test_types_reported:
                if len([test for test in result if test["test_name"] == test_type]) > 1 and \
                        len([result_obj for result_obj in result if result_obj["test_name"] == test_type and result_obj["item"] is None]) > 0:
                    raise Exception(error_template + " (ItemIsNoneButMoreThanSingleResultReturned). CANNOT CONTINUE.")

            log_message = {
                "event_type": "auto_posture_evaluator",
                "service": cur_tester.declare_tested_service(),
                "provider": cur_tester.declare_tested_provider(),
                "test_id": test_id
            }
            for result_obj in result:
                cur_log_message = log_message.copy()
                cur_log_message["timestamp"] = result_obj["timestamp"] * 1000
                cur_log_message["event_sub_type"] = result_obj["test_name"]
                cur_log_message["resource_type"] = result_obj["item_type"]
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
