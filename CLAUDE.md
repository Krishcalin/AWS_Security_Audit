# CLAUDE.md

## Project Overview

AWS-Security-Scanner is a collection of Bash scripts that perform automated security audits of AWS cloud environments. The scripts are aligned to the **CIS AWS Foundations Benchmark v3.0** and produce color-coded terminal output with PASS/FAIL/WARN verdicts plus evidence files saved to a timestamped output directory.

**License:** GPL-3.0

## Repository Structure

```
AWS-Security-Scanner/
├── aws_security_audit_scripts.sh   # Original audit script (8 sections, ~420 lines)
├── aws_security_audit_enhanced.sh  # Enhanced audit script (16 sections, ~1430 lines)
├── README.md                       # Minimal project description
└── LICENSE                         # GPL-3.0
```

There are **two** audit scripts. Both share the same architecture but differ in scope:

| Script | Sections | Covers |
|--------|----------|--------|
| `aws_security_audit_scripts.sh` | 1-8 | IAM, S3, VPC, Logging, KMS, EC2, ECR, Backup |
| `aws_security_audit_enhanced.sh` | 1-16 | Everything above + RDS, Glacier, SNS, SQS, CloudFront, Route 53, Bedrock, Bedrock Agents |

## Prerequisites

- **AWS CLI v2** configured with valid credentials
- **Python 3.8+** with `boto3` installed
- **IAM permissions:** the executing identity needs the `SecurityAudit` AWS-managed policy (read-only audit access across services)
- Default region: `eu-west-1` (override via `AWS_DEFAULT_REGION` env var)

## How to Run

```bash
# Run the original (shorter) audit
bash aws_security_audit_scripts.sh

# Run the enhanced (comprehensive) audit
bash aws_security_audit_enhanced.sh

# Override region
AWS_DEFAULT_REGION=us-east-1 bash aws_security_audit_enhanced.sh
```

Output is written to `aws_audit_<ACCOUNT_ID>_<TIMESTAMP>/` in the working directory.

## Script Architecture

Both scripts follow an identical pattern:

1. **Shell setup:** `set -euo pipefail`, region/account resolution, output dir creation
2. **Helper functions:** `log()`, `pass()`, `fail()`, `warn()` — color-coded output with counters
3. **Sectioned checks:** each section is a labeled block (e.g., `SECTION 1: IDENTITY & ACCESS MANAGEMENT`)
4. **Hybrid Bash + Python:** simple checks use AWS CLI directly; complex checks use inline Python heredocs (`python3 - <<'PYEOF' ... PYEOF`) with `boto3`
5. **Summary:** final PASS/FAIL/WARN tallies and evidence manifest

### Check ID Convention

Each check has a prefixed ID matching the service domain:

| Prefix | Domain |
|--------|--------|
| `IAM-XX` | Identity & Access Management |
| `S3-XX` | S3 Storage |
| `VPC-XX` | Network / VPC |
| `LOG-XX` | Logging & Monitoring |
| `ENC-XX` | Encryption & KMS |
| `EC2-XX` | Compute |
| `CNT-XX` | Containers (ECR) |
| `BCK-XX` | Backup & DR |
| `RDS-XX` | RDS Databases |
| `GLC-XX` | S3 Glacier |
| `SNS-XX` | SNS Topics |
| `SQS-XX` | SQS Queues |
| `CFN-XX` | CloudFront |
| `R53-XX` | Route 53 |
| `BDR-XX` | Bedrock |
| `AGT-XX` | Bedrock Agents |

## Key Conventions for AI Assistants

### Code Style

- Scripts use `#!/usr/bin/env bash` with `set -euo pipefail`
- ANSI color codes are defined at the top: `RED`, `GREEN`, `YELLOW`, `BLUE`, `NC`
- All complex logic is in inline Python 3 heredocs (`<<'PYEOF'`), not separate `.py` files
- Python blocks use `boto3` directly (no wrapper libraries)
- Environment variable `OUTPUT_DIR` is used by Python blocks via `os.environ.get('OUTPUT_DIR', '.')`
- Broad exception handling is intentional — checks should never crash the entire audit

### Section Pattern

When adding new checks, follow this template:

```bash
# ─────────────────────────────────────────────────────────────────────────────
# SECTION N: SERVICE NAME
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ SERVICE NAME CHECKS ══${NC}"

log "SVC-01: Description of check"
python3 - <<'PYEOF'
import boto3
client = boto3.client('service-name')
# ... check logic ...
# Use ANSI codes for output:
#   \033[0;32m[PASS]\033[0m  for passing checks
#   \033[0;31m[FAIL]\033[0m  for failing checks
#   \033[1;33m[WARN]\033[0m  for warnings
#   \033[0;34m[INFO]\033[0m  for informational output
PYEOF
```

### Adding New Service Checks

1. Add a new numbered section at the end (before the final summary block)
2. Define a new check ID prefix (e.g., `DDB-XX` for DynamoDB)
3. Update the evidence manifest service list in the `AUDIT_MANIFEST.txt` generation block at the bottom of the enhanced script
4. Keep both scripts in sync if the check applies to the base scope — otherwise add only to the enhanced script

### Important Considerations

- **Read-only by design:** these scripts must never modify AWS resources. All API calls should be describe/get/list operations only.
- **No credentials in code:** scripts rely on the ambient AWS CLI profile or IAM role. Never hardcode keys or secrets.
- **The two scripts share code but are independent files.** Sections 1-8 are duplicated across both. Changes to shared sections should be applied to both files.
- **Evidence files** (CSV, JSON) are saved to the output directory. The manifest at the end catalogs them.
- **PASS/FAIL/WARN counters** are managed by the shell helper functions. Python blocks print ANSI-colored output directly but do NOT increment the shell counters (this is a known limitation).

## Testing

There is no automated test suite. To validate changes:

1. Ensure the script parses cleanly: `bash -n aws_security_audit_enhanced.sh`
2. Run against a real or test AWS account with `SecurityAudit` permissions
3. Verify the output shows correct PASS/FAIL/WARN for known resource states
4. Confirm the evidence directory is created and populated

## Git Workflow

- The `master` branch is the primary branch
- Commit messages describe the change directly (no conventional commits prefix required)
- The repository does not use CI/CD pipelines, pre-commit hooks, or automated releases
