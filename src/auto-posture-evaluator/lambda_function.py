import auto_posture_evaluator

def lambda_handler(event, context):
    tester = auto_posture_evaluator.AutoPostureEvaluator()
    tester.run_tests()

auto_posture_evaluator.AutoPostureEvaluator().run_tests()
