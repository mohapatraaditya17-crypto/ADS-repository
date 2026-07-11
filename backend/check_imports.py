import sys
sys.path.insert(0, '.')

modules = [
    'app.tools.crowdstrike.client_factory',
    'app.tools.crowdstrike.detections',
    'app.tools.crowdstrike.incidents',
    'app.tools.crowdstrike.hosts',
    'app.tools.crowdstrike.intel',
    'app.tools.crowdstrike.policies',
    'app.tools.crowdstrike.audit',
    'app.tools.crowdstrike.users',
    'app.tools.crowdstrike.spotlight',
    'app.tools.crowdstrike.discover',
    'app.tools.crowdstrike.sensor',
    'app.tools.crowdstrike.iocs',
    'app.tools.crowdstrike.processes',
    'app.tools.crowdstrike.network',
    'app.tools.crowdstrike.identity',
    'app.tools.crowdstrike.correlation',
    'app.tools.crowdstrike.metrics',
    'app.tools.report_writer',
    'app.agents.orchestrator',
    'app.agents.soc_analyst',
    'app.agents.report_generator',
]

errors = []
for m in modules:
    try:
        __import__(m)
        print(f'  OK  {m}')
    except Exception as e:
        errors.append((m, str(e)))
        print(f'  FAIL {m}: {e}')

print()
if errors:
    print(f'RESULT: {len(errors)} IMPORT ERRORS FOUND')
    for m, e in errors:
        print(f'  - {m}: {e}')
else:
    print('RESULT: ALL 21 MODULES IMPORTED SUCCESSFULLY')
