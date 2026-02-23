#!/usr/bin/env bash
# ============================================================================
# AWS Cloud Security Audit — Master Testing Script
# Aligned to: CIS AWS Foundations Benchmark v3.0
# Requirements: AWS CLI v2, Python 3.8+, boto3, SecurityAudit IAM policy
# Usage: bash aws_security_audit_scripts.sh [--region eu-west-1]

# Author: Krishnendu De
# ============================================================================

set -euo pipefail

REGION="${AWS_DEFAULT_REGION:-eu-west-1}"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="aws_audit_${ACCOUNT}_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0

log()  { echo -e "${BLUE}[*]${NC} $1"; }
pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; ((WARN++)); }

echo "======================================================================"
echo " AWS Cloud Security Audit"
echo " Account : $ACCOUNT"
echo " Region  : $REGION"
echo " Output  : $OUTPUT_DIR"
echo "======================================================================"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1: IDENTITY & ACCESS MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ IAM SECURITY CHECKS ══${NC}"

log "IAM-01/02: Root account MFA and access keys"
SUMMARY=$(aws iam get-account-summary --query 'SummaryMap' --output json)
ROOT_MFA=$(echo "$SUMMARY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('AccountMFAEnabled', 0))")
ROOT_KEYS=$(echo "$SUMMARY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('AccountAccessKeysPresent', 0))")
[ "$ROOT_MFA" -eq 1 ] && pass "IAM-01: Root MFA is enabled" || fail "IAM-01: Root MFA is NOT enabled — CRITICAL"
[ "$ROOT_KEYS" -eq 0 ] && pass "IAM-02: No root access keys present" || fail "IAM-02: Root access keys EXIST — CRITICAL remove immediately"

log "Generating IAM Credential Report..."
aws iam generate-credential-report > /dev/null 2>&1 || true
sleep 6
aws iam get-credential-report --query 'Content' --output text | base64 -d > "$OUTPUT_DIR/credential_report.csv"
pass "IAM credential report saved to $OUTPUT_DIR/credential_report.csv"

log "IAM-04: Checking console users without MFA"
python3 - <<'PYEOF'
import csv, os
report = os.environ.get('OUTPUT_DIR', '.') + '/credential_report.csv'
no_mfa = []
with open(report) as f:
    for row in csv.DictReader(f):
        if row['user'] == '<root_account>': continue
        if row.get('password_enabled') == 'true' and row.get('mfa_active') == 'false':
            no_mfa.append(row['user'])
if no_mfa:
    for u in no_mfa:
        print(f"\033[0;31m[FAIL]\033[0m IAM-04: Console user WITHOUT MFA: {u}")
else:
    print(f"\033[0;32m[PASS]\033[0m IAM-04: All console users have MFA enabled")
PYEOF

log "IAM-05: Password policy"
aws iam get-account-password-policy --output json > "$OUTPUT_DIR/password_policy.json" 2>/dev/null && {
    python3 - <<'PYEOF'
import json, os
with open(os.environ.get('OUTPUT_DIR','.')+'/password_policy.json') as f:
    p = json.load(f)['PasswordPolicy']
issues = []
if p.get('MinimumPasswordLength', 0) < 14: issues.append(f"MinLength={p.get('MinimumPasswordLength')} (need ≥14)")
if not p.get('RequireSymbols'): issues.append("RequireSymbols=false")
if not p.get('RequireNumbers'): issues.append("RequireNumbers=false")
if not p.get('RequireUppercaseCharacters'): issues.append("RequireUppercase=false")
if p.get('MaxPasswordAge', 999) > 90: issues.append(f"MaxAge={p.get('MaxPasswordAge')} (need ≤90)")
if not p.get('PreventPasswordReuse') or p.get('PasswordReusePrevention', 0) < 24: issues.append("PasswordReuse<24")
if issues:
    print(f"\033[0;31m[FAIL]\033[0m IAM-05: Password policy issues: {', '.join(issues)}")
else:
    print(f"\033[0;32m[PASS]\033[0m IAM-05: Password policy meets requirements")
PYEOF
} || fail "IAM-05: No account password policy set"

log "IAM-06: Stale access keys (>90 days)"
python3 - <<'PYEOF'
import csv, os
from datetime import datetime, timezone
report = os.environ.get('OUTPUT_DIR', '.') + '/credential_report.csv'
with open(report) as f:
    for row in csv.DictReader(f):
        for k in ['access_key_1', 'access_key_2']:
            if row.get(f'{k}_active') == 'true':
                rotated = row.get(f'{k}_last_rotated', '')
                if rotated and rotated not in ('N/A', 'no_information'):
                    age = (datetime.now(timezone.utc) - datetime.fromisoformat(rotated)).days
                    if age > 90:
                        print(f"\033[0;31m[FAIL]\033[0m IAM-06: {row['user']} {k} is {age} days old (rotated: {rotated[:10]})")
                    else:
                        print(f"\033[0;32m[PASS]\033[0m IAM-06: {row['user']} {k} age {age}d OK")
PYEOF

log "IAM-10: Access Analyzer enabled in all regions"
for REGION_CHECK in $(aws ec2 describe-regions --query 'Regions[*].RegionName' --output text 2>/dev/null); do
    COUNT=$(aws accessanalyzer list-analyzers --region "$REGION_CHECK" --query 'length(analyzers)' --output text 2>/dev/null || echo 0)
    [ "$COUNT" -gt 0 ] && pass "IAM-10: Access Analyzer active in $REGION_CHECK" || fail "IAM-10: No Access Analyzer in $REGION_CHECK"
done

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2: S3 SECURITY
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ S3 SECURITY CHECKS ══${NC}"

log "S3-01: Account-level Block Public Access"
aws s3control get-public-access-block --account-id "$ACCOUNT" --output json > "$OUTPUT_DIR/s3_account_bpa.json" 2>/dev/null && {
    python3 -c "
import json
with open('$OUTPUT_DIR/s3_account_bpa.json') as f:
    cfg = json.load(f)['PublicAccessBlockConfiguration']
if all(cfg.values()):
    print('\033[0;32m[PASS]\033[0m S3-01: Account-level Block Public Access fully enabled')
else:
    disabled = [k for k,v in cfg.items() if not v]
    print(f'\033[0;31m[FAIL]\033[0m S3-01: Block Public Access not fully enabled — Disabled: {disabled}')
"
} || fail "S3-01: Could not retrieve account-level Block Public Access settings"

log "S3-01/S3-03/S3-05: Per-bucket security scan"
python3 - <<'PYEOF'
import boto3, json, os
s3 = boto3.client('s3')
out = os.environ.get('OUTPUT_DIR', '.')
results = []
try:
    buckets = s3.list_buckets().get('Buckets', [])
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m Cannot list S3 buckets: {e}")
    exit()
for b in buckets:
    bname = b['Name']
    # Block Public Access
    try:
        bpa = s3.get_public_access_block(Bucket=bname)['PublicAccessBlockConfiguration']
        if all(bpa.values()):
            print(f"\033[0;32m[PASS]\033[0m S3-01: BPA enabled | {bname}")
        else:
            print(f"\033[0;31m[FAIL]\033[0m S3-01: BPA NOT fully enabled | {bname}")
    except Exception:
        print(f"\033[0;31m[FAIL]\033[0m S3-01: No BPA config | {bname}")
    # Encryption
    try:
        enc = s3.get_bucket_encryption(Bucket=bname)['ServerSideEncryptionConfiguration']
        alg = enc['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
        print(f"\033[0;32m[PASS]\033[0m S3-03: Encryption={alg} | {bname}")
    except Exception:
        print(f"\033[0;31m[FAIL]\033[0m S3-03: No default encryption | {bname}")
    # Logging
    try:
        log = s3.get_bucket_logging(Bucket=bname).get('LoggingEnabled')
        if log:
            print(f"\033[0;32m[PASS]\033[0m S3-05: Access logging enabled | {bname}")
        else:
            print(f"\033[1;33m[WARN]\033[0m S3-05: Access logging disabled | {bname}")
    except Exception:
        pass
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3: VPC / NETWORK
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ NETWORK SECURITY CHECKS ══${NC}"

log "VPC-01: Security Groups — risky ports open to 0.0.0.0/0"
python3 - <<'PYEOF'
import boto3
ec2 = boto3.client('ec2')
RISKY_PORTS = {22: 'SSH', 3389: 'RDP', 1433: 'MSSQL', 3306: 'MySQL',
               5432: 'PostgreSQL', 27017: 'MongoDB', 6379: 'Redis',
               9200: 'Elasticsearch', 9300: 'Elasticsearch', 8080: 'HTTP-alt', 445: 'SMB'}
found_any = False
for sg in ec2.describe_security_groups()['SecurityGroups']:
    for perm in sg.get('IpPermissions', []):
        fp = perm.get('FromPort', 0)
        tp = perm.get('ToPort', 65535)
        open_cidrs = [r['CidrIp'] for r in perm.get('IpRanges', []) if r['CidrIp'] in ('0.0.0.0/0',)]
        open_cidrs += [r['CidrIpv6'] for r in perm.get('Ipv6Ranges', []) if r['CidrIpv6'] == '::/0']
        if open_cidrs:
            for port, svc in RISKY_PORTS.items():
                if fp <= port <= tp:
                    print(f"\033[0;31m[FAIL]\033[0m VPC-01: SG {sg['GroupId']} ({sg.get('GroupName','')}) "
                          f"exposes port {port}/{svc} to {', '.join(open_cidrs)}")
                    found_any = True
if not found_any:
    print(f"\033[0;32m[PASS]\033[0m VPC-01: No Security Groups expose high-risk ports to 0.0.0.0/0")
PYEOF

log "VPC-03: VPC Flow Logs"
python3 - <<'PYEOF'
import boto3
ec2 = boto3.client('ec2')
vpcs = {v['VpcId']: v for v in ec2.describe_vpcs()['Vpcs']}
fl_vpcs = {fl['ResourceId'] for fl in ec2.describe_flow_logs()['FlowLogs']}
for vid in vpcs:
    is_default = vpcs[vid].get('IsDefault', False)
    if vid in fl_vpcs:
        print(f"\033[0;32m[PASS]\033[0m VPC-03: Flow Logs enabled | {vid}")
    else:
        sev = "WARN" if is_default else "FAIL"
        print(f"\033[{'1;33' if sev=='WARN' else '0;31'}m[{sev}]\033[0m VPC-03: No Flow Logs | {vid}{'  (default VPC)' if is_default else ''}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4: LOGGING & MONITORING
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ LOGGING & MONITORING CHECKS ══${NC}"

log "LOG-01: CloudTrail configuration"
python3 - <<'PYEOF'
import boto3
ct = boto3.client('cloudtrail')
trails = ct.describe_trails(includeShadowTrails=False)['trailList']
if not trails:
    print("\033[0;31m[FAIL]\033[0m LOG-01: No CloudTrail trails configured — CRITICAL")
else:
    for t in trails:
        issues = []
        if not t.get('IsMultiRegionTrail'): issues.append("not multi-region")
        if not t.get('LogFileValidationEnabled'): issues.append("log validation OFF")
        status = ct.get_trail_status(Name=t['Name'])
        if not status.get('IsLogging'): issues.append("LOGGING IS OFF")
        if issues:
            print(f"\033[0;31m[FAIL]\033[0m LOG-01: Trail '{t['Name']}' issues: {', '.join(issues)}")
        else:
            print(f"\033[0;32m[PASS]\033[0m LOG-01: Trail '{t['Name']}' OK (multi-region, validation enabled, logging active)")
PYEOF

log "LOG-03: AWS Config recorder status"
python3 - <<'PYEOF'
import boto3
cfg = boto3.client('config')
try:
    recorders = cfg.describe_configuration_recorder_status()['ConfigurationRecordersStatus']
    for r in recorders:
        if r.get('recording'):
            print(f"\033[0;32m[PASS]\033[0m LOG-03: AWS Config recording | {r['name']}")
        else:
            print(f"\033[0;31m[FAIL]\033[0m LOG-03: AWS Config NOT recording | {r['name']}")
    if not recorders:
        print("\033[0;31m[FAIL]\033[0m LOG-03: No AWS Config recorders found")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m LOG-03: {e}")
PYEOF

log "LOG-04: GuardDuty enabled in current region"
python3 - <<'PYEOF'
import boto3
gd = boto3.client('guardduty')
detectors = gd.list_detectors().get('DetectorIds', [])
if not detectors:
    print("\033[0;31m[FAIL]\033[0m LOG-04: GuardDuty NOT enabled — CRITICAL")
else:
    for did in detectors:
        d = gd.get_detector(DetectorId=did)
        status = d.get('Status', 'DISABLED')
        color = '0;32' if status == 'ENABLED' else '0;31'
        print(f"\033[{color}m{'[PASS]' if status=='ENABLED' else '[FAIL]'}\033[0m LOG-04: GuardDuty {status} | {did}")
PYEOF

log "LOG-05: Security Hub standards"
python3 - <<'PYEOF'
import boto3
sh = boto3.client('securityhub')
try:
    standards = sh.get_enabled_standards()['StandardsSubscriptions']
    if standards:
        for s in standards:
            print(f"\033[0;32m[PASS]\033[0m LOG-05: Security Hub standard: {s.get('StandardsArn','').split('/')[-2]} — {s.get('StandardsStatus','')}")
    else:
        print("\033[0;31m[FAIL]\033[0m LOG-05: Security Hub enabled but no standards subscribed")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m LOG-05: Security Hub not enabled or error: {e}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5: ENCRYPTION & KMS
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ ENCRYPTION & KMS CHECKS ══${NC}"

log "ENC-03: KMS key rotation status"
python3 - <<'PYEOF'
import boto3
kms = boto3.client('kms')
paginator = kms.get_paginator('list_keys')
found = False
for page in paginator.paginate():
    for key in page['Keys']:
        kid = key['KeyId']
        try:
            meta = kms.describe_key(KeyId=kid)['KeyMetadata']
            if meta.get('KeyManager') == 'CUSTOMER' and meta.get('KeyState') == 'Enabled':
                found = True
                rotation = kms.get_key_rotation_status(KeyId=kid).get('KeyRotationEnabled', False)
                desc = meta.get('Description') or kid[:8]
                color = '0;32' if rotation else '0;31'
                verdict = 'PASS' if rotation else 'FAIL [ENC-03]'
                print(f"\033[{color}m[{verdict}]\033[0m KMS key rotation={'ON' if rotation else 'OFF'} | {desc}")
        except Exception:
            pass
if not found:
    print("\033[1;33m[WARN]\033[0m ENC-03: No customer-managed KMS keys found")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6: COMPUTE / EC2
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ COMPUTE SECURITY CHECKS ══${NC}"

log "EC2-04: IMDSv2 enforcement"
python3 - <<'PYEOF'
import boto3
ec2 = boto3.client('ec2')
paginator = ec2.get_paginator('describe_instances')
all_pass = True
for page in paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]):
    for res in page['Reservations']:
        for i in res['Instances']:
            iid = i['InstanceId']
            name = next((t['Value'] for t in i.get('Tags', []) if t['Key'] == 'Name'), iid)
            tokens = i.get('MetadataOptions', {}).get('HttpTokens', 'optional')
            if tokens != 'required':
                print(f"\033[0;31m[FAIL]\033[0m EC2-04: IMDSv2 not enforced (HttpTokens={tokens}) | {name}")
                all_pass = False
if all_pass:
    print("\033[0;32m[PASS]\033[0m EC2-04: All EC2 instances enforce IMDSv2")
PYEOF

log "EC2-06: EBS volume encryption"
python3 - <<'PYEOF'
import boto3
ec2 = boto3.client('ec2')
volumes = ec2.describe_volumes()['Volumes']
unenc = [v for v in volumes if not v.get('Encrypted', False)]
enc   = [v for v in volumes if v.get('Encrypted', False)]
print(f"\033[0;32m[PASS]\033[0m EC2-06: Encrypted volumes: {len(enc)}")
for v in unenc:
    print(f"\033[0;31m[FAIL]\033[0m EC2-06: UNENCRYPTED EBS volume: {v['VolumeId']} State={v['State']}")
PYEOF

log "EC2-05: Public IP check on EC2 instances"
python3 - <<'PYEOF'
import boto3
ec2 = boto3.client('ec2')
paginator = ec2.get_paginator('describe_instances')
for page in paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]):
    for res in page['Reservations']:
        for i in res['Instances']:
            if i.get('PublicIpAddress'):
                name = next((t['Value'] for t in i.get('Tags', []) if t['Key'] == 'Name'), i['InstanceId'])
                print(f"\033[1;33m[WARN]\033[0m EC2-05: Public IP {i['PublicIpAddress']} on instance: {name} — verify if intentional")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7: CONTAINER SECURITY
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ CONTAINER SECURITY CHECKS ══${NC}"

log "CNT-01: ECR scan-on-push"
python3 - <<'PYEOF'
import boto3
ecr = boto3.client('ecr')
try:
    repos = ecr.describe_repositories()['repositories']
    for repo in repos:
        scan = repo.get('imageScanningConfiguration', {}).get('scanOnPush', False)
        enc = repo.get('encryptionConfiguration', {}).get('encryptionType', 'AES256')
        verdict = "\033[0;32m[PASS]\033[0m" if scan else "\033[0;31m[FAIL]\033[0m CNT-01:"
        print(f"{verdict} ECR scan-on-push={'ON' if scan else 'OFF'} | {repo['repositoryName']} (enc={enc})")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m CNT-01: {e}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8: BACKUP
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ BACKUP & DR CHECKS ══${NC}"

log "BCK-01: AWS Backup vaults"
python3 - <<'PYEOF'
import boto3
bk = boto3.client('backup')
try:
    vaults = bk.list_backup_vaults()['BackupVaultList']
    if vaults:
        for v in vaults:
            print(f"\033[0;32m[PASS]\033[0m BCK-01: Backup vault: {v['BackupVaultName']} (RecoveryPoints: {v.get('NumberOfRecoveryPoints',0)})")
    else:
        print("\033[0;31m[FAIL]\033[0m BCK-01: No AWS Backup vaults configured")
    plans = bk.list_backup_plans()['BackupPlansList']
    if not plans:
        print("\033[0;31m[FAIL]\033[0m BCK-01: No AWS Backup plans configured")
    else:
        for p in plans:
            print(f"\033[0;32m[PASS]\033[0m BCK-01: Backup plan: {p['BackupPlanName']}")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m BCK-01: {e}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "======================================================================"
echo -e " ${GREEN}PASS${NC}: $PASS  |  ${RED}FAIL${NC}: $FAIL  |  ${YELLOW}WARN${NC}: $WARN"
echo " Evidence saved to: $OUTPUT_DIR/"
echo "======================================================================"
