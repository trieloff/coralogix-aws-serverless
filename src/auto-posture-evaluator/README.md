# Auto posture evaluator

## Proof of Concept
This is a proof that we can keep up-to-date the reporting across client and server using protobuf and grpc calls
### Generating models (optional)
#### Requirements
 * [protodep](https://github.com/stormcat24/protodep)
 * [python-betterproto](https://github.com/danielgtaylor/python-betterproto)

#### Actions
 1. Run `make` to do the following:
    1. Create temp dir to pull the models using `protodep`
    2. Generates the models
    3. Moves the needed files to `./model`
 2. What needs to be done by the developer
    1. Manually remove the backend code from `./model/__init__.py`
    2. Manually add the authorization head for the client in `./model/__init__.py`
    ```python
    class SecurityReportIngestionServiceStub(betterproto.ServiceStub):
        async def post_security_report(
    -        self, *, security_report: "SecurityReport" = None
    +        self, *, api_key: str, security_report: "SecurityReport" = None
        ) -> "PostSecurityReportResponse":

            request = PostSecurityReportRequest()
            if security_report is not None:
                request.security_report = security_report

            return await self._unary_unary(
                route="/com.coralogix.xdr.ingestion.v1.SecurityReportIngestionService/PostSecurityReport",
                request=request,
                response_type=PostSecurityReportResponse,
    +           metadata=[('authorization', api_key)]
            )
    ```

### Tester requirements

Each test has to extend from the `poc_interface.TesterInterface` which implements the following 3 method:

    def declare_tested_service(self) -> str:

    def declare_tested_provider(self) -> str:

    def run_tests(self) -> List["TestReport"]:

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

Take into account that `TestReport` fields are mandatory for successful reporting