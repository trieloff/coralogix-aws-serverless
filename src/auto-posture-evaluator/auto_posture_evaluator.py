import asyncio
import datetime
import os
import uuid
from asyncio import AbstractEventLoop

import importlib
import sys
from grpclib.client import Channel
from model import SecurityReportTestResult, SecurityReportIngestionServiceStub, SecurityReportContext, SecurityReport, \
    SecurityReportTestResultResult
from model.helper import struct_from_dict


testers_module_names = []
if not os.environ.get('TESTER_LIST'):
    raise Exception("Missing the TESTER_LIST environment variable. CANNOT CONTINUE")
tester_list = os.environ.get('TESTER_LIST').split(',')
for module in tester_list:
    module_name = "testers." + module + "_tester"
    testers_module_names.append(module_name)
    importlib.import_module(module_name)
del module


def _adapter(log_message):
    log_message["name"] = log_message.pop("test_name")
    log_message["result"] = log_message.pop("test_result")
    return log_message


def _to_model(log_message, start_time, end_time) -> "SecurityReportTestResult":
    converted_log_message = _adapter(log_message)
    additional_data = {}
    test_result = SecurityReportTestResultResult.TEST_FAILED
    if log_message["result"] == "no_issue_found":
        test_result = SecurityReportTestResultResult.TEST_PASSED
    for key in converted_log_message.keys():
        if not hasattr(SecurityReportTestResult, key) and converted_log_message[key]:
            additional_data[key] = converted_log_message[key]
    return SecurityReportTestResult(
        name=converted_log_message["name"],
        start_time=start_time,
        end_time=end_time,
        item=converted_log_message["item"],
        item_type=converted_log_message["item_type"],
        result=test_result,
        additional_data=struct_from_dict(additional_data)
    )


class AutoPostureEvaluator:
    def __init__(self):
        if not os.environ.get('API_KEY'):
            raise Exception("Missing the API_KEY environment variable. CANNOT CONTINUE")

        # Configuration for grpc endpoint
        endpoint = os.environ.get("CORALOGIX_ENDPOINT_HOST")  # eg.: ng-api-grpc.dev-shared.coralogix.net
        port = os.environ.get("CORALOGIX_ENDPOINT_PORT", "443")
        self.channel = Channel(host=endpoint, port=int(port), ssl=True)
        self.client = SecurityReportIngestionServiceStub(channel=self.channel)
        self.api_key = os.environ.get('API_KEY')
        self.tests = []
        self.application_name = os.environ.get('APPLICATION_NAME', 'NO_APP_NAME')
        self.subsystem_name = os.environ.get('SUBSYSTEM_NAME', 'NO_SUB_NAME')
        for tester_module in testers_module_names:
            if "Tester" in sys.modules[tester_module].__dict__:
                self.tests.append(sys.modules[tester_module].__dict__["Tester"])

    def run_tests(self):
        execution_id = str(uuid.uuid4())
        lambda_start_timestamp = datetime.datetime.now()
        for i in range(0, len(self.tests)):
            cur_test_start_timestamp = datetime.datetime.now()
            tester = self.tests[i]
            print("INFO: Start " + str(tester) + " tester")
            try:
                cur_tester = tester()
                tester_result = cur_tester.run_tests()
                cur_test_end_timestamp = datetime.datetime.now()
            except Exception as exTesterException:
                print("WARN: The tester " + str(testers_module_names[i]) +
                      " has crashed with the following exception during 'run_tests()'. SKIPPED: " +
                      str(exTesterException))
                continue

            error_template = "The result object from the tester " + cur_tester.declare_tested_service() + \
                             " does not match the required standard"
            if tester_result is None:
                print(error_template + " (ResultIsNone).")
                continue
            if not isinstance(tester_result, list):
                print(error_template + " (NotArray).")
                continue
            if not tester_result:
                print(error_template + " (Empty array).")
                continue
            else:
                for result_obj in tester_result:
                    if "timestamp" not in result_obj or "item" not in result_obj or "item_type" \
                            not in result_obj or "test_result" not in result_obj:
                        print(error_template + " (FieldsMissing). CANNOT CONTINUE.")
                        continue
                    if result_obj["item"] is None:
                        print(error_template + " (ItemIsNone). CANNOT CONTINUE.")
                        continue
                    if not isinstance(result_obj["timestamp"], float):
                        print(error_template + " (ItemDateIsNotFloat). CANNOT CONTINUE.")
                        continue
                    if len(str(int(result_obj["timestamp"]))) != 10:
                        print(error_template + " (ItemDateIsNotTenDigitsIntPart). CANNOT CONTINUE.")
                        continue
            security_report_test_result_list = list(map(lambda x: _to_model(x,
                                                                            cur_test_start_timestamp,
                                                                            cur_test_end_timestamp), tester_result))
            context = SecurityReportContext(
                provider=cur_tester.declare_tested_provider(),
                service=cur_tester.declare_tested_service(),
                execution_id=execution_id,
                application_name=self.application_name,
                computer_name="CoralogixServerlessLambda",
                subsystem_name=self.subsystem_name
            )
            report = SecurityReport(context=context, test_results=security_report_test_result_list)
            print("DEBUG: Sent " + str(len(security_report_test_result_list)) + " events for " +
                  str(testers_module_names[i]) + " time taken " +
                  str(cur_test_end_timestamp - cur_test_start_timestamp))
            loop: AbstractEventLoop = asyncio.get_event_loop()
            try:
                loop.run_until_complete(
                    self.client.post_security_report(api_key=self.api_key, security_report=report))
            except Exception as ex:
                print("ERROR: Failed to send " + str(len(security_report_test_result_list)) + " for tester " +
                      str(testers_module_names[i]) + " events due to the following exception: " + str(ex))
        print("Lambda taken " + str(datetime.datetime.now()-lambda_start_timestamp))
        self.channel.close()

