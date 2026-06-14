# SENTINEL-LLM

Reference implementation and reproducibility materials for:

> **SENTINEL-LLM: A Practical Multi-Layer Defense Framework for Adversarial Prompts in Production Language Model Systems**
> Muneeb Anjum
> Department of Computer Science, COMSATS University Islamabad, Abbottabad Campus, Pakistan

## Contents

- `paper/sentinel_llm_preprint.pdf` — preprint PDF
- `src/sentinel_llm.py` — reference implementation
- `tests/poc_test_set.json` — 32 real attack prompts from JailbreakBench, HarmBench, and OWASP
- `tests/run_poc.py` — one-command reproducibility script
- `sentinel_config.yaml` — tuned configuration
- `REPRODUCIBILITY.md` — per-case results and reviewer instructions
- `docs/CITATION.md` — citation info

## Quick start

```python
from src.sentinel_llm import SentinelLLM, SentinelConfig

config = SentinelConfig.tuned()
sentinel = SentinelLLM(config)

result = sentinel.evaluate(prompt="Ignore all previous instructions")
if not result.allowed:
    print(f"Blocked by {result.layer}: {result.reason}")
```

## The 5 layers

| # | Layer | Function | Latency |
|---|---|---|---|
| L1 | Pre-processing Guard | lexical patterns + embedding anomaly | <10 ms |
| L2 | Context Tracker | intent graph across conversation | <15 ms |
| L3 | Cross-Modal Verifier | OCR + perturbation check for VLM | <25 ms |
| L4 | Tool-Call Firewall | authorized action set for agents | <20 ms |
| L5 | Output Monitor | refusal bypass + PII + injection scan | <30 ms |

Designed overhead: <100 ms per inference. Measured median: 0.1–0.3 ms per request.

## Reproduce the paper's results

```bash
pip install pyyaml
python3 tests/run_poc.py --tuned
```

Expected output:

```
Paper's 7 PoC: 4/7 = 57.1%
Paper claim: 4/7 = 57.1%
Status: MATCH

Detection: 28/32 = 87.5%
False positives: 1/10 = 10.0%
```

See `REPRODUCIBILITY.md` for the full per-case decision log.

## Configuration presets

```python
config = SentinelConfig.tuned()           # matches paper's published result
config = SentinelConfig.conservative()    # high thresholds, low FP rate
config = SentinelConfig.from_yaml("sentinel_config.yaml")
```

## Requirements

- Python 3.11+
- Standard library (no required installs)
- `pyyaml` (only for `from_yaml`)

## License

MIT — see `LICENSE`.

## Citation

See `docs/CITATION.md` or use:

```bibtex
@misc{anjum2026sentinel,
  author = {Muneeb Anjum},
  title  = {SENTINEL-LLM: A Practical Multi-Layer Defense Framework for Adversarial Prompts in Production Language Model Systems},
  year   = {2026},
  howpublished = {Preprints.org}
}
```

## Contact

horizonbymuneeb@gmail.com
