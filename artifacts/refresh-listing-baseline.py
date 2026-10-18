"""Accept only reviewed catalog listing changes, preserving all execution baselines."""
import json, pathlib, subprocess
path=pathlib.Path('tests/fixtures/compatibility/baseline.json')
original=path.read_bytes()
before=json.loads(original)
try:
    subprocess.run(['php','tests/CompatibilityBaselineTest.php','--record-baseline'],check=True)
    after=json.loads(path.read_bytes())
    changed=[key for key in before if before[key]!=after.get(key)]
    if changed!=['rule_listing']:
        raise RuntimeError(f'Unexpected compatibility changes: {changed}')
    print('Reviewed change is confined to rule_listing; execution baselines unchanged.')
except BaseException:
    path.write_bytes(original)
    raise
