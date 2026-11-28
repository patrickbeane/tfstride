"""Run with .venv/bin/python -m tests.benchmarks.gcp_gcs_contexts --help."""

from __future__ import annotations

import argparse
import json
from statistics import median
from time import perf_counter

from tests.helpers.gcp_gcs_evaluation import analyze_with_counts, plan_file
from tests.helpers.gcp_gcs_plan import build_benchmark_resources
from tfstride.app import TfStride


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure full GCP analysis and GCS context construction separately.")
    parser.add_argument("--scenario", choices=("pubsub", "gcs"), default="pubsub")
    parser.add_argument("--workloads", type=_positive_int, nargs="+", default=[10, 30, 60])
    parser.add_argument("--repeat", type=_positive_int, default=3)
    args = parser.parse_args()
    engine = TfStride()
    for workloads in args.workloads:
        resources = build_benchmark_resources(workloads, args.scenario)
        with plan_file(resources) as path:
            engine.analyze_plan(path)  # Warm imports and rule registration before timing.
            times: list[float] = []
            for _ in range(args.repeat):
                started = perf_counter()
                engine.analyze_plan(path)
                times.append(perf_counter() - started)
            result, counts = analyze_with_counts(path, engine, grant_queries=True)
        print(
            json.dumps(
                {
                    "scenario": args.scenario,
                    "workloads": workloads,
                    "resources": len(resources),
                    "median_seconds": round(median(times), 6),
                    "runs_seconds": [round(elapsed, 6) for elapsed in times],
                    "findings": len(result.findings),
                    **counts,
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
