"""Where does parsing spend its time on a realistic description?"""

import cProfile
import io
import pstats
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.engine.parser import ArchitectureParser

DESCRIPTION = """
A patient portal built in React is served through CloudFront to clinicians and patients.
The portal calls a public API edge on Amazon API Gateway, which routes to an accounts
service and a records service running on EKS. The accounts service reads and writes an
Aurora PostgreSQL database. The records service stores documents in an S3 exports bucket
and publishes events to a Kafka queue. A settlement worker consumes the queue and calls
an external laboratory partner over HTTPS. Secrets are read from AWS Secrets Manager.
Audit logs are shipped to Splunk. The API edge enforces rate limiting per API key and a
WAF fronts CloudFront. The clinician portal has no MFA for support staff. The exports
bucket is not encrypted at rest. Traffic between pods is not restricted by network
policies. The settlement worker accepts webhook callbacks without signature verification.
An admin console shares the same authentication as the patient portal.
"""


def main() -> None:
    parser = ArchitectureParser()
    parser.parse(DESCRIPTION)  # warm any caches and model loading

    start = time.perf_counter()
    for _ in range(3):
        parser.parse(DESCRIPTION)
    print(f"parse seconds (mean of 3): {(time.perf_counter() - start) / 3:.3f}")

    profile = cProfile.Profile()
    profile.enable()
    parser.parse(DESCRIPTION)
    profile.disable()
    stream = io.StringIO()
    pstats.Stats(profile, stream=stream).sort_stats("tottime").print_stats(14)
    print(stream.getvalue())


if __name__ == "__main__":
    main()
