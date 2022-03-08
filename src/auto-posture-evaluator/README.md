# Auto posture evaluator


### Tester requirements

Each test has to extend from the `interfaces.py` which implements the following 3 method:

    def declare_tested_service(self) -> str:

    def declare_tested_provider(self) -> str:

    def run_tests(self) -> list:

Have the following environment variables set (`*` fields are mandatory):
 * `CORALOGIX_ENDPOINT_HOST`*
 * `SUBSYSTEM_NAME`
 * `APPLICATION_NAME`
 * `API_KEY`*
 * `PRIVATE_KEY`*
 * `AWS_PROFILE`*
 * `AWS_DEFAULT_REGION`*
 * `CORALOGIX_ENDPOINT_PORT`

Check individual tests for further env variables
