import auto_posture_evaluator


async def lambda_handler(event, context):
    tester = auto_posture_evaluator.AutoPostureEvaluator()
    await tester.run_tests()

auto_posture_evaluator.AutoPostureEvaluator().run_tests()
