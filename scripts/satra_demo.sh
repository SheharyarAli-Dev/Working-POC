#!/usr/bin/env bash
set -euo pipefail

echo "=================================================="
echo "  ASENT SATRA-RV End-to-End Demonstration Script  "
echo "=================================================="

PROJECT_DIR="/mnt/c/Users/Administrator/Desktop/Mid"
cd "$PROJECT_DIR"
source ~/projects/Working-POC/.venv-satra/bin/activate

echo "[1/4] Checking Ollama Status and Connection..."
python3 -c "
from backend.satra.settings import load_settings, responds
s = load_settings()
print(f'Ollama Endpoint: {s.ollama_endpoint}')
print(f'Model: {s.model_name}')
print(f'Online: {responds(s.ollama_endpoint)}')
"

echo "[2/4] Verifying Trusted Assets Manifest..."
python3 -c "
from backend.satra.trust import verify_manifest
res = verify_manifest()
assert res['valid'], 'Trusted manifest verification failed: ' + str(res)
print('Trusted specification manifest verified OK.')
"

echo "[3/4] Running Full SATRA Unit & Sandbox Test Suite..."
pytest tests/test_satra_*.py -q

echo "[4/4] Executing Decision Engine & Recommit Demo..."
python3 -c "
from backend.satra.decision_engine import DecisionEngine
engine = DecisionEngine()
ctx = {
    'allowlist_valid': True,
    'manifest_valid': True,
    'ast_localized': True,
    'regions': [{'file': 'app/main.py'}],
    'contract': {'rule_id': 'AUTHZ.IDOR.001'},
    'baseline_execution': {'available': True, 'exit_code': 0, 'passed': 5},
    'oracle': {'accepted': True, 'valid_counterfactual': True, 'diagnosis': 'PRESERVED_WITHIN_MODEL'},
    'repeat_execution': {'available': True, 'exit_code': 0},
}
verdict = engine.evaluate_gates(ctx)
print('Decision Matrix Verdict:', verdict['final_verdict'])
print('Passed Gates:', verdict['gates_passed'], '/', verdict['gates_total'])
assert verdict['final_verdict'] == 'ACCEPT'
"

echo "=================================================="
echo "  SATRA-RV Demonstration Completed Successfully!   "
echo "=================================================="
