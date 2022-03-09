import asyncio
import datetime
import json
import os
import time
import uuid
from asyncio import AbstractEventLoop

import importlib
import sys
from grpclib.client import Channel
from model import SecurityReportTestResult, SecurityReportIngestionServiceStub, SecurityReportContext, SecurityReport, \
    SecurityReportTestResultResult
from model.helper import struct_from_dict


testers_module_names = []
for module in os.listdir(os.path.dirname(__file__) + '/testers'):
    if module.startswith('_') or module[-3:] != '.py':
        continue
    module_name = "testers." + module[:-3]
    testers_module_names.append(module_name)
    importlib.import_module(module_name)
del module


def _adapter(log_message):
    log_message["name"] = log_message.pop("test_name")
    log_message["result"] = log_message.pop("test_result")
    return log_message


def _to_model(log_message, execution_id, provider, service, start_time, end_time) -> "SecurityReportTestResult":
    converted_log_message = _adapter(log_message)
    additional_data = {}
    test_result = SecurityReportTestResultResult.TEST_FAILED
    if log_message["result"] == "no_issue_found":
        test_result = SecurityReportTestResultResult.TEST_PASSED
    _update_frameworks_classifications(log_message)
    for key in converted_log_message.keys():
        if not hasattr(SecurityReportTestResult, key) and converted_log_message[key]:
            additional_data[key] = converted_log_message[key]
    return SecurityReportTestResult(
        provider=provider,
        service=service,
        name=converted_log_message["name"],
        start_time=start_time,
        end_time=end_time,
        item=converted_log_message["item"],
        item_type=converted_log_message["item_type"],
        result=test_result,
        execution_id=execution_id,
        additional_data=struct_from_dict(additional_data)
)


class AutoPostureEvaluator:
    def __init__(self):
        if not os.environ.get('PRIVATE_KEY'):
            raise Exception("Missing the PRIVATE_KEY environment variable. CANNOT CONTINUE")

        # Configuration for grpc endpoint
        endpoint = os.environ.get("CORALOGIX_ENDPOINT_HOST")  # eg.: api.coralogix.net
        port = os.environ.get("CORALOGIX_ENDPOINT_PORT", "443")
        self.send_to_coralogix = os.environ.get("SEND_TO_CORALOGIX", False)
        self.channel = Channel(host=endpoint, port=int(port), ssl=True)
        self.client = SecurityReportIngestionServiceStub(channel=self.channel)
        self.api_key = os.environ.get('API_KEY')
        self.private_key = os.environ.get('PRIVATE_KEY')
        self.context = SecurityReportContext(
            private_key=self.private_key,
            application_name=os.environ.get('APPLICATION_NAME', 'NO_APP_NAME'),
            subsystem_name=os.environ.get('SUBSYSTEM_NAME', 'NO_SUB_NAME'),
            computer_name="CoralogixServerlessLambda")
        self.tests = []
        for tester_module in testers_module_names:
            if "Tester" in sys.modules[tester_module].__dict__:
                self.tests.append(sys.modules[tester_module].__dict__["Tester"])

    def run_tests(self):
        execution_id = str(uuid)
        for i in range(0, len(self.tests)):
            cur_test_start_timestamp = datetime.datetime.now()
            tester = self.tests[i]
            try:
                cur_tester = tester()
                tester_result = cur_tester.run_tests()
                cur_test_end_timestamp = datetime.datetime.now()
            except Exception as exTesterException:
                print("WARN: The tester " + str(testers_module_names[i]) + " has crashed with the following exception during 'run_tests()'. SKIPPED: " + str(exTesterException))
                continue

            error_template = "The result object from the tester " + cur_tester.declare_tested_service() + " does not match the required standard"
            if tester_result is None:
                raise Exception(error_template + " (ResultIsNone). CANNOT CONTINUE.")
            if not isinstance(tester_result, list):
                raise Exception(error_template + " (NotArray). CANNOT CONTINUE.")
            else:
                for result_obj in tester_result:
                    if "timestamp" not in result_obj or "item" not in result_obj or "item_type" not in result_obj or "test_result" not in result_obj:
                        raise Exception(error_template + " (FieldsMissing). CANNOT CONTINUE.")
                    if result_obj["item"] is None:
                        raise Exception(error_template + " (ItemIsNone). CANNOT CONTINUE.")
                    if not isinstance(result_obj["timestamp"], float):
                        raise Exception(error_template + " (ItemDateIsNotFloat). CANNOT CONTINUE.")
                    if len(str(int(result_obj["timestamp"]))) != 10:
                        raise Exception(error_template + " (ItemDateIsNotTenDigitsIntPart). CANNOT CONTINUE.")
            try:

                security_report_test_result_list = list(map(lambda x: _to_model(x,
                                                                                execution_id,
                                                                                cur_tester.declare_tested_provider(),
                                                                                cur_tester.declare_tested_service(),
                                                                                cur_test_start_timestamp,
                                                                                cur_test_end_timestamp), tester_result))
                report = SecurityReport(context=self.context, test_results=security_report_test_result_list)
                print("DEBUG: Sent " + str(len(security_report_test_result_list)) + " events for " + str(testers_module_names[i]))
                loop: AbstractEventLoop = asyncio.get_event_loop()
                loop.run_until_complete(
                    self.client.post_security_report(api_key=self.api_key, security_report=report))
            except Exception as ex:
                print("ERROR: Failed to send " + str(len(security_report_test_result_list)) + " for tester " +
                      str(testers_module_names[i]) + " events due to the following exception: " + str(ex))
            self.channel.close()


def _update_frameworks_classifications(cur_log_message):
        # TODO: Update this method with a real table
        cur_log_message["classifications"] = {
            "HIPPA": "",
            "PCI-DSS": "",
            "SOC2": "",
            "ISO": "",
            "CIS": "",
            "NIST": ""
        }
        test_name_length = len(cur_log_message["name"])
        test_name_first_part_length = len(cur_log_message["name"].split("_", maxsplit=1)[0])
        if test_name_length < 25:
            cur_log_message["classifications"]["HIPPA"] = str(test_name_first_part_length) + "." + str(test_name_length)
        if 23 <= test_name_length < 35:
            cur_log_message["classifications"]["PCI-DSS"] = str(test_name_first_part_length) + "." + str(test_name_length)
        if 32 <= test_name_length < 42:
            cur_log_message["classifications"]["SOC2"] = str(test_name_first_part_length) + "." + str(test_name_length)
        if 39 <= test_name_length < 45:
            cur_log_message["classifications"]["ISO"] = str(test_name_first_part_length) + "." + str(test_name_length)
        if 42 <= test_name_length < 50:
            cur_log_message["classifications"]["CIS"] = str(test_name_first_part_length) + "." + str(test_name_length)
        if test_name_length > 48:
            cur_log_message["classifications"]["NIST"] = str(test_name_first_part_length) + "." + str(test_name_length)
