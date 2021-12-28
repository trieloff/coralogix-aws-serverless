import datetime
import json
import os
import time
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

        for i in range(0, len(self.tests)):
            tester = self.tests[i]
            try:
                cur_tester = tester()
                result = cur_tester.run_tests()
            except Exception as exTesterException:
                print("WARN: The tester " + str(testers_module_names[i]) + " has crashed with the following exception during 'run_tests()'. SKIPPED: " + str(exTesterException))
                continue

            error_template = "The result object from the tester " + cur_tester.declare_tested_service() + " does not match the required standard"
            if result is None:
                raise Exception(error_template + " (ResultIsNone). CANNOT CONTINUE.")
            if not isinstance(result, list):
                raise Exception(error_template + " (NotArray). CANNOT CONTINUE.")
            else:
                for result_obj in result:
                    if "timestamp" not in result_obj or "item" not in result_obj or "item_type" not in result_obj or "test_result" not in result_obj:
                        raise Exception(error_template + " (FieldsMissing). CANNOT CONTINUE.")
                    if result_obj["item"] is None:
                        raise Exception(error_template + " (ItemIsNone). CANNOT CONTINUE.")
                    if not isinstance(result_obj["timestamp"], float):
                        raise Exception(error_template + " (ItemDateIsNotFloat). CANNOT CONTINUE.")
                    if len(str(int(result_obj["timestamp"]))) != 10:
                        raise Exception(error_template + " (ItemDateIsNotTenDigitsIntPart). CANNOT CONTINUE.")

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
                for key in result_obj.keys():
                    if key not in cur_log_message and result_obj[key]:
                        cur_log_message[key] = result_obj[key]
                cur_log_message["item"] = result_obj["item"]

                self.update_frameworks_classifications(cur_log_message)

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

    def update_frameworks_classifications(self, cur_log_message):
        # TODO: Update this method with a real table
        cur_log_message["classifications"] = {
            "HIPPA": False,
            "PCI-DSS": False,
            "SOC2": False,
            "ISO": False,
            "CIS": False,
            "NIST": False
        }
        if len(cur_log_message["event_sub_type"]) < 25:
            cur_log_message["classifications"]["HIPPA"] = True
        if 23 <= len(cur_log_message["event_sub_type"]) < 35:
            cur_log_message["classifications"]["PCI DSS"] = True
        if 32 <= len(cur_log_message["event_sub_type"]) < 42:
            cur_log_message["classifications"]["SOC2"] = True
        if 39 <= len(cur_log_message["event_sub_type"]) < 45:
            cur_log_message["classifications"]["ISO"] = True
        if 42 <= len(cur_log_message["event_sub_type"]) < 50:
            cur_log_message["classifications"]["CIS"] = True
        if len(cur_log_message["event_sub_type"]) > 48:
            cur_log_message["classifications"]["NIST"] = True

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
