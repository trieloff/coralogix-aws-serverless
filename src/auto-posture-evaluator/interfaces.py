class TesterInterface:
    def declare_tested_service(self) -> str:
        pass

    def declare_tested_provider(self) -> str:
        pass

    def declare_tested_resource_type(self) -> str:
        pass

    def declare_required_args(self) -> list:
        pass

    def run_tests(self, args_object) -> list:
        pass
