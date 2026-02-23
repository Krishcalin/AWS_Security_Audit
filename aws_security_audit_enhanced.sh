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
# SECTION 9: AMAZON RDS SECURITY
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ AMAZON RDS SECURITY CHECKS ══${NC}"

log "RDS-01: RDS instances — encryption at rest"
python3 - <<'PYEOF'
import boto3
rds = boto3.client('rds')
try:
    paginator = rds.get_paginator('describe_db_instances')
    found = False
    for page in paginator.paginate():
        for db in page['DBInstances']:
            found = True
            iid  = db['DBInstanceIdentifier']
            enc  = db.get('StorageEncrypted', False)
            engine = db.get('Engine', 'unknown')
            verdict = "\033[0;32m[PASS]\033[0m" if enc else "\033[0;31m[FAIL]\033[0m RDS-01:"
            print(f"{verdict} Storage encryption={'ON' if enc else 'OFF'} | {iid} ({engine})")
    if not found:
        print("\033[1;33m[WARN]\033[0m RDS-01: No RDS instances found in this region")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m RDS-01: {e}")
PYEOF

log "RDS-02: RDS instances — publicly accessible"
python3 - <<'PYEOF'
import boto3
rds = boto3.client('rds')
try:
    paginator = rds.get_paginator('describe_db_instances')
    all_private = True
    for page in paginator.paginate():
        for db in page['DBInstances']:
            iid    = db['DBInstanceIdentifier']
            pub    = db.get('PubliclyAccessible', False)
            engine = db.get('Engine', 'unknown')
            if pub:
                print(f"\033[0;31m[FAIL]\033[0m RDS-02: DB is PUBLICLY ACCESSIBLE | {iid} ({engine}) — CRITICAL")
                all_private = False
    if all_private:
        print("\033[0;32m[PASS]\033[0m RDS-02: No RDS instances are publicly accessible")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m RDS-02: {e}")
PYEOF

log "RDS-03: RDS automated backups and backup retention ≥7 days"
python3 - <<'PYEOF'
import boto3
rds = boto3.client('rds')
try:
    paginator = rds.get_paginator('describe_db_instances')
    for page in paginator.paginate():
        for db in page['DBInstances']:
            iid        = db['DBInstanceIdentifier']
            retention  = db.get('BackupRetentionPeriod', 0)
            multi_az   = db.get('MultiAZ', False)
            if retention == 0:
                print(f"\033[0;31m[FAIL]\033[0m RDS-03: Automated backups DISABLED | {iid}")
            elif retention < 7:
                print(f"\033[1;33m[WARN]\033[0m RDS-03: Backup retention={retention}d (recommend ≥7) | {iid}")
            else:
                print(f"\033[0;32m[PASS]\033[0m RDS-03: Backup retention={retention}d | {iid}")
            maz = "\033[0;32m[PASS]\033[0m" if multi_az else "\033[1;33m[WARN]\033[0m"
            print(f"{maz} RDS-03: Multi-AZ={'ON' if multi_az else 'OFF'} | {iid}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m RDS-03: {e}")
PYEOF

log "RDS-04: RDS — deletion protection and minor version auto-upgrade"
python3 - <<'PYEOF'
import boto3
rds = boto3.client('rds')
try:
    paginator = rds.get_paginator('describe_db_instances')
    for page in paginator.paginate():
        for db in page['DBInstances']:
            iid        = db['DBInstanceIdentifier']
            del_prot   = db.get('DeletionProtection', False)
            auto_minor = db.get('AutoMinorVersionUpgrade', False)
            print(f"{'\\033[0;32m[PASS]\\033[0m' if del_prot else '\\033[0;31m[FAIL]\\033[0m RDS-04:'} Deletion protection={'ON' if del_prot else 'OFF'} | {iid}")
            print(f"{'\\033[0;32m[PASS]\\033[0m' if auto_minor else '\\033[1;33m[WARN]\\033[0m'} RDS-04: Auto minor upgrade={'ON' if auto_minor else 'OFF'} | {iid}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m RDS-04: {e}")
PYEOF

log "RDS-05: RDS — CloudWatch enhanced monitoring and audit logging"
python3 - <<'PYEOF'
import boto3
rds = boto3.client('rds')
try:
    paginator = rds.get_paginator('describe_db_instances')
    for page in paginator.paginate():
        for db in page['DBInstances']:
            iid        = db['DBInstanceIdentifier']
            monitoring = db.get('MonitoringInterval', 0)
            logs       = db.get('EnabledCloudwatchLogsExports', [])
            print(f"{'\\033[0;32m[PASS]\\033[0m' if monitoring > 0 else '\\033[1;33m[WARN]\\033[0m'} RDS-05: Enhanced monitoring interval={monitoring}s | {iid}")
            if logs:
                print(f"\033[0;32m[PASS]\033[0m RDS-05: CloudWatch log exports={logs} | {iid}")
            else:
                print(f"\033[1;33m[WARN]\033[0m RDS-05: No CloudWatch log exports configured | {iid}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m RDS-05: {e}")
PYEOF

log "RDS-06: RDS snapshots — public visibility check"
python3 - <<'PYEOF'
import boto3
rds = boto3.client('rds')
try:
    snaps = rds.describe_db_snapshots(SnapshotType='manual')['DBSnapshots']
    public_snaps = []
    for s in snaps:
        attrs = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=s['DBSnapshotIdentifier'])
        for a in attrs['DBSnapshotAttributesResult']['DBSnapshotAttributes']:
            if a['AttributeName'] == 'restore' and 'all' in a.get('AttributeValues', []):
                public_snaps.append(s['DBSnapshotIdentifier'])
    if public_snaps:
        for snap in public_snaps:
            print(f"\033[0;31m[FAIL]\033[0m RDS-06: RDS snapshot is PUBLICLY ACCESSIBLE: {snap}")
    else:
        print(f"\033[0;32m[PASS]\033[0m RDS-06: No RDS snapshots are publicly accessible ({len(snaps)} manual snapshots checked)")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m RDS-06: {e}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 10: AMAZON S3 GLACIER SECURITY
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ AMAZON S3 GLACIER SECURITY CHECKS ══${NC}"

log "GLC-01: Glacier vaults — access policies and public access"
python3 - <<'PYEOF'
import boto3, json
glacier = boto3.client('glacier')
try:
    vaults = glacier.list_vaults(accountId='-')['VaultList']
    if not vaults:
        print("\033[1;33m[WARN]\033[0m GLC-01: No Glacier vaults found in this region")
    for v in vaults:
        vname = v['VaultName']
        vrn   = v['VaultARN']
        size  = v.get('SizeInBytes', 0)
        count = v.get('NumberOfArchives', 0)
        print(f"\033[0;34m[INFO]\033[0m GLC-01: Vault: {vname} | Archives: {count} | Size: {size/1024/1024:.1f} MB")
        # Check vault access policy
        try:
            policy = glacier.get_vault_access_policy(accountId='-', vaultName=vname)
            doc = json.loads(policy['policy']['Policy'])
            for stmt in doc.get('Statement', []):
                principal = stmt.get('Principal', {})
                effect    = stmt.get('Effect', '')
                # Flag wildcard Allow principals
                if effect == 'Allow':
                    p_val = principal if isinstance(principal, str) else principal.get('AWS', '')
                    if p_val == '*' or p_val == ['*']:
                        print(f"\033[0;31m[FAIL]\033[0m GLC-01: Vault '{vname}' has wildcard (Principal:*) Allow in access policy — CRITICAL")
                    else:
                        print(f"\033[0;32m[PASS]\033[0m GLC-01: Vault '{vname}' access policy scoped (no wildcard principal)")
        except glacier.exceptions.ResourceNotFoundException:
            print(f"\033[1;33m[WARN]\033[0m GLC-01: Vault '{vname}' has no access policy — verify intentional")
        except Exception as pe:
            print(f"\033[1;33m[WARN]\033[0m GLC-01: Could not read policy for '{vname}': {pe}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m GLC-01: {e}")
PYEOF

log "GLC-02: Glacier vaults — vault lock (WORM) status"
python3 - <<'PYEOF'
import boto3
glacier = boto3.client('glacier')
try:
    vaults = glacier.list_vaults(accountId='-')['VaultList']
    for v in vaults:
        vname = v['VaultName']
        try:
            lock = glacier.get_vault_lock(accountId='-', vaultName=vname)
            state = lock.get('State', 'Unknown')
            created = lock.get('CreationDate', 'N/A')
            color = '0;32' if state == 'Locked' else '1;33'
            print(f"\033[{color}m{'[PASS]' if state=='Locked' else '[WARN]'}\033[0m GLC-02: Vault Lock state={state} | {vname} (created: {created[:10] if created != 'N/A' else 'N/A'})")
        except glacier.exceptions.ResourceNotFoundException:
            print(f"\033[1;33m[WARN]\033[0m GLC-02: No Vault Lock policy on '{vname}' — WORM protection absent")
        except Exception as le:
            print(f"\033[1;33m[WARN]\033[0m GLC-02: Could not check lock for '{vname}': {le}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m GLC-02: {e}")
PYEOF

log "GLC-03: Glacier — SNS notifications configured for vaults"
python3 - <<'PYEOF'
import boto3
glacier = boto3.client('glacier')
try:
    vaults = glacier.list_vaults(accountId='-')['VaultList']
    for v in vaults:
        vname = v['VaultName']
        try:
            notif = glacier.get_vault_notifications(accountId='-', vaultName=vname)
            topic = notif['vaultNotificationConfig'].get('SNSTopic', 'None')
            events = notif['vaultNotificationConfig'].get('Events', [])
            print(f"\033[0;32m[PASS]\033[0m GLC-03: Notifications configured | {vname} → {topic} | Events: {events}")
        except glacier.exceptions.ResourceNotFoundException:
            print(f"\033[1;33m[WARN]\033[0m GLC-03: No SNS notifications on vault '{vname}' — job completion alerts absent")
        except Exception as ne:
            print(f"\033[1;33m[WARN]\033[0m GLC-03: Could not check notifications for '{vname}': {ne}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m GLC-03: {e}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 11: AMAZON SNS SECURITY
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ AMAZON SNS SECURITY CHECKS ══${NC}"

log "SNS-01: SNS topics — encryption at rest (SSE-KMS)"
python3 - <<'PYEOF'
import boto3
sns = boto3.client('sns')
try:
    paginator = sns.get_paginator('list_topics')
    found = False
    for page in paginator.paginate():
        for t in page['Topics']:
            found = True
            arn  = t['TopicArn']
            name = arn.split(':')[-1]
            attrs = sns.get_topic_attributes(TopicArn=arn)['Attributes']
            kms_key = attrs.get('KmsMasterKeyId', '')
            enc     = bool(kms_key)
            print(f"{'\\033[0;32m[PASS]\\033[0m' if enc else '\\033[1;33m[WARN]\\033[0m'} SNS-01: SSE-KMS={'ON ('+kms_key+')' if enc else 'OFF'} | {name}")
    if not found:
        print("\033[1;33m[WARN]\033[0m SNS-01: No SNS topics found in this region")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m SNS-01: {e}")
PYEOF

log "SNS-02: SNS topics — access policy (no wildcard Principal)"
python3 - <<'PYEOF'
import boto3, json
sns = boto3.client('sns')
try:
    paginator = sns.get_paginator('list_topics')
    for page in paginator.paginate():
        for t in page['Topics']:
            arn  = t['TopicArn']
            name = arn.split(':')[-1]
            attrs = sns.get_topic_attributes(TopicArn=arn)['Attributes']
            policy = json.loads(attrs.get('Policy', '{"Statement":[]}'))
            issues = []
            for stmt in policy.get('Statement', []):
                principal = stmt.get('Principal', {})
                effect    = stmt.get('Effect', '')
                condition = stmt.get('Condition', {})
                p_val = principal if isinstance(principal, str) else principal.get('AWS', '') or principal.get('Service', '')
                if effect == 'Allow' and (p_val == '*' or p_val == ['*']) and not condition:
                    issues.append(f"Action={stmt.get('Action','*')} allows wildcard Principal with no Condition")
            if issues:
                for i in issues:
                    print(f"\033[0;31m[FAIL]\033[0m SNS-02: Overly permissive policy on '{name}': {i}")
            else:
                print(f"\033[0;32m[PASS]\033[0m SNS-02: Access policy OK (no unconstrained wildcard) | {name}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m SNS-02: {e}")
PYEOF

log "SNS-03: SNS topics — HTTPS delivery enforcement (no HTTP subscriptions)"
python3 - <<'PYEOF'
import boto3
sns = boto3.client('sns')
try:
    paginator = sns.get_paginator('list_topics')
    for page in paginator.paginate():
        for t in page['Topics']:
            arn  = t['TopicArn']
            name = arn.split(':')[-1]
            subs = sns.list_subscriptions_by_topic(TopicArn=arn).get('Subscriptions', [])
            for sub in subs:
                protocol = sub.get('Protocol', '')
                endpoint = sub.get('Endpoint', '')
                if protocol == 'http':
                    print(f"\033[0;31m[FAIL]\033[0m SNS-03: Insecure HTTP subscription on topic '{name}' → {endpoint}")
                elif protocol == 'https':
                    print(f"\033[0;32m[PASS]\033[0m SNS-03: HTTPS subscription on '{name}' → {endpoint[:60]}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m SNS-03: {e}")
PYEOF

log "SNS-04: SNS — cross-account subscriptions and access"
python3 - <<'PYEOF'
import boto3
sns   = boto3.client('sns')
sts   = boto3.client('sts')
my_acct = sts.get_caller_identity()['Account']
try:
    paginator = sns.get_paginator('list_subscriptions')
    for page in paginator.paginate():
        for sub in page['Subscriptions']:
            endpoint = sub.get('Endpoint', '')
            # Detect cross-account ARN subscriptions
            if endpoint.startswith('arn:aws') and ':' in endpoint:
                parts = endpoint.split(':')
                if len(parts) > 4 and parts[4] and parts[4] != my_acct:
                    print(f"\033[1;33m[WARN]\033[0m SNS-04: Cross-account subscription detected | Topic: {sub['TopicArn'].split(':')[-1]} → Account: {parts[4]}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m SNS-04: {e}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 12: AMAZON SQS SECURITY
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ AMAZON SQS SECURITY CHECKS ══${NC}"

log "SQS-01: SQS queues — encryption at rest (SSE-KMS or SSE-SQS)"
python3 - <<'PYEOF'
import boto3
sqs = boto3.client('sqs')
try:
    queues = sqs.list_queues().get('QueueUrls', [])
    if not queues:
        print("\033[1;33m[WARN]\033[0m SQS-01: No SQS queues found in this region")
    for url in queues:
        name  = url.split('/')[-1]
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=['All'])['Attributes']
        kms   = attrs.get('KmsMasterKeyId', '')
        sse   = attrs.get('SqsManagedSseEnabled', 'false')
        if kms:
            print(f"\033[0;32m[PASS]\033[0m SQS-01: SSE-KMS={kms} | {name}")
        elif sse.lower() == 'true':
            print(f"\033[0;32m[PASS]\033[0m SQS-01: SSE-SQS (managed) enabled | {name}")
        else:
            print(f"\033[0;31m[FAIL]\033[0m SQS-01: No encryption at rest | {name}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m SQS-01: {e}")
PYEOF

log "SQS-02: SQS queues — access policy (no unauthenticated public access)"
python3 - <<'PYEOF'
import boto3, json
sqs = boto3.client('sqs')
try:
    queues = sqs.list_queues().get('QueueUrls', [])
    for url in queues:
        name  = url.split('/')[-1]
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=['Policy'])['Attributes']
        policy_str = attrs.get('Policy', '')
        if not policy_str:
            print(f"\033[1;33m[WARN]\033[0m SQS-02: No resource policy on queue '{name}' — access governed by IAM only")
            continue
        policy = json.loads(policy_str)
        issues = []
        for stmt in policy.get('Statement', []):
            effect    = stmt.get('Effect', '')
            principal = stmt.get('Principal', {})
            condition = stmt.get('Condition', {})
            p_val     = principal if isinstance(principal, str) else principal.get('AWS', '')
            if effect == 'Allow' and (p_val == '*' or p_val == ['*']) and not condition:
                issues.append(stmt.get('Action', '*'))
        if issues:
            print(f"\033[0;31m[FAIL]\033[0m SQS-02: Queue '{name}' allows unauthenticated access to: {issues}")
        else:
            print(f"\033[0;32m[PASS]\033[0m SQS-02: Queue policy OK | {name}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m SQS-02: {e}")
PYEOF

log "SQS-03: SQS queues — Dead Letter Queue (DLQ) configured"
python3 - <<'PYEOF'
import boto3, json
sqs = boto3.client('sqs')
try:
    queues = sqs.list_queues().get('QueueUrls', [])
    for url in queues:
        name  = url.split('/')[-1]
        if name.endswith('-dlq') or name.endswith('_dlq') or 'dead' in name.lower():
            continue   # skip DLQs themselves
        attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=['RedrivePolicy'])['Attributes']
        redrive = attrs.get('RedrivePolicy', '')
        if redrive:
            dlq_arn = json.loads(redrive).get('deadLetterTargetArn', 'N/A')
            print(f"\033[0;32m[PASS]\033[0m SQS-03: DLQ configured | {name} → {dlq_arn.split(':')[-1]}")
        else:
            print(f"\033[1;33m[WARN]\033[0m SQS-03: No DLQ configured for queue '{name}' — unprocessed messages may be lost")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m SQS-03: {e}")
PYEOF

log "SQS-04: SQS queues — message retention and visibility timeout"
python3 - <<'PYEOF'
import boto3
sqs = boto3.client('sqs')
try:
    queues = sqs.list_queues().get('QueueUrls', [])
    for url in queues:
        name  = url.split('/')[-1]
        attrs = sqs.get_queue_attributes(
            QueueUrl=url,
            AttributeNames=['MessageRetentionPeriod', 'VisibilityTimeout', 'QueueType']
        )['Attributes']
        retention   = int(attrs.get('MessageRetentionPeriod', 0))
        visibility  = int(attrs.get('VisibilityTimeout', 0))
        ret_days    = retention / 86400
        ret_warn    = ret_days > 14  # >14 days could mean messages are stuck
        print(f"{'\\033[1;33m[WARN]\\033[0m' if ret_warn else '\\033[0;32m[PASS]\\033[0m'} SQS-04: Retention={ret_days:.1f}d VisibilityTimeout={visibility}s | {name}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m SQS-04: {e}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 13: AMAZON CLOUDFRONT SECURITY
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ AMAZON CLOUDFRONT SECURITY CHECKS ══${NC}"

log "CFN-01: CloudFront distributions — HTTPS-only (no HTTP viewer protocol)"
python3 - <<'PYEOF'
import boto3
cf = boto3.client('cloudfront')
try:
    dists = cf.list_distributions().get('DistributionList', {}).get('Items', [])
    if not dists:
        print("\033[1;33m[WARN]\033[0m CFN-01: No CloudFront distributions found")
    for d in dists:
        did     = d['Id']
        domain  = d.get('DomainName', did)
        status  = d.get('Status', 'Unknown')
        # Default cache behaviour viewer protocol policy
        default_cb  = d.get('DefaultCacheBehavior', {})
        viewer_pol  = default_cb.get('ViewerProtocolPolicy', 'allow-all')
        if viewer_pol == 'allow-all':
            print(f"\033[0;31m[FAIL]\033[0m CFN-01: HTTP allowed (ViewerProtocolPolicy=allow-all) | {domain} [{status}]")
        elif viewer_pol == 'redirect-to-https':
            print(f"\033[1;33m[WARN]\033[0m CFN-01: HTTP redirects to HTTPS (consider https-only) | {domain}")
        else:
            print(f"\033[0;32m[PASS]\033[0m CFN-01: HTTPS-only enforced | {domain} [{status}]")
        # Check all cache behaviours
        for cb in d.get('CacheBehaviors', {}).get('Items', []):
            path = cb.get('PathPattern', '?')
            pol  = cb.get('ViewerProtocolPolicy', 'allow-all')
            if pol == 'allow-all':
                print(f"\033[0;31m[FAIL]\033[0m CFN-01: HTTP allowed on path '{path}' | {domain}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m CFN-01: {e}")
PYEOF

log "CFN-02: CloudFront — minimum TLS protocol version"
python3 - <<'PYEOF'
import boto3
cf = boto3.client('cloudfront')
INSECURE_PROTOCOLS = {'SSLv3', 'TLSv1', 'TLSv1_2016', 'TLSv1.1_2016'}
try:
    dists = cf.list_distributions().get('DistributionList', {}).get('Items', [])
    for d in dists:
        did    = d['Id']
        domain = d.get('DomainName', did)
        viewer_cert = d.get('ViewerCertificate', {})
        min_proto   = viewer_cert.get('MinimumProtocolVersion', 'TLSv1')
        cert_src    = viewer_cert.get('CertificateSource', 'cloudfront')
        if min_proto in INSECURE_PROTOCOLS:
            print(f"\033[0;31m[FAIL]\033[0m CFN-02: Insecure TLS version '{min_proto}' | {domain}")
        else:
            print(f"\033[0;32m[PASS]\033[0m CFN-02: TLS min version={min_proto} cert={cert_src} | {domain}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m CFN-02: {e}")
PYEOF

log "CFN-03: CloudFront — WAF Web ACL association"
python3 - <<'PYEOF'
import boto3
cf = boto3.client('cloudfront')
try:
    dists = cf.list_distributions().get('DistributionList', {}).get('Items', [])
    for d in dists:
        did    = d['Id']
        domain = d.get('DomainName', did)
        waf    = d.get('WebACLId', '')
        if waf:
            print(f"\033[0;32m[PASS]\033[0m CFN-03: WAF Web ACL attached | {domain}")
        else:
            print(f"\033[0;31m[FAIL]\033[0m CFN-03: No WAF Web ACL on distribution | {domain} — at risk from OWASP/DDoS")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m CFN-03: {e}")
PYEOF

log "CFN-04: CloudFront — access logging enabled"
python3 - <<'PYEOF'
import boto3
cf = boto3.client('cloudfront')
try:
    paginator = cf.get_paginator('list_distributions')
    for page in paginator.paginate():
        for d in page.get('DistributionList', {}).get('Items', []):
            did     = d['Id']
            domain  = d.get('DomainName', did)
            # Need full config for logging details
            config  = cf.get_distribution_config(Id=did)['DistributionConfig']
            logging = config.get('Logging', {})
            enabled = logging.get('Enabled', False)
            bucket  = logging.get('Bucket', '')
            if enabled:
                print(f"\033[0;32m[PASS]\033[0m CFN-04: Access logging enabled → {bucket} | {domain}")
            else:
                print(f"\033[0;31m[FAIL]\033[0m CFN-04: Access logging DISABLED | {domain}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m CFN-04: {e}")
PYEOF

log "CFN-05: CloudFront — Origin Protocol Policy (HTTPS to origin)"
python3 - <<'PYEOF'
import boto3
cf = boto3.client('cloudfront')
try:
    dists = cf.list_distributions().get('DistributionList', {}).get('Items', [])
    for d in dists:
        domain = d.get('DomainName', d['Id'])
        for origin in d.get('Origins', {}).get('Items', []):
            oid         = origin.get('Id', 'N/A')
            custom_cfg  = origin.get('CustomOriginConfig', {})
            origin_proto = custom_cfg.get('OriginProtocolPolicy', '')
            if origin_proto == 'http-only':
                print(f"\033[0;31m[FAIL]\033[0m CFN-05: Origin '{oid}' uses HTTP-only protocol | {domain}")
            elif origin_proto == 'match-viewer':
                print(f"\033[1;33m[WARN]\033[0m CFN-05: Origin '{oid}' uses match-viewer (may allow HTTP) | {domain}")
            elif origin_proto == 'https-only':
                print(f"\033[0;32m[PASS]\033[0m CFN-05: Origin '{oid}' enforces HTTPS | {domain}")
            elif not origin_proto:
                # S3 origins use OAC/OAI — no custom origin config
                oac = origin.get('S3OriginConfig', {}).get('OriginAccessIdentity', '')
                oac_ctrl = origin.get('OriginAccessControlId', '')
                if oac_ctrl:
                    print(f"\033[0;32m[PASS]\033[0m CFN-05: S3 origin '{oid}' uses OAC | {domain}")
                elif oac:
                    print(f"\033[1;33m[WARN]\033[0m CFN-05: S3 origin '{oid}' uses legacy OAI (migrate to OAC) | {domain}")
                else:
                    print(f"\033[0;31m[FAIL]\033[0m CFN-05: S3 origin '{oid}' has no OAC/OAI — bucket may be publicly accessible | {domain}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m CFN-05: {e}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 14: AMAZON ROUTE 53 SECURITY
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ AMAZON ROUTE 53 SECURITY CHECKS ══${NC}"

log "R53-01: Route 53 hosted zones — query logging enabled"
python3 - <<'PYEOF'
import boto3
r53 = boto3.client('route53')
try:
    zones = r53.list_hosted_zones()['HostedZones']
    if not zones:
        print("\033[1;33m[WARN]\033[0m R53-01: No Route 53 hosted zones found")
    # Get all query logging configs for efficient lookup
    try:
        log_configs = r53.list_query_logging_configs()['QueryLoggingConfigs']
        logged_zones = {c['HostedZoneId'] for c in log_configs}
    except Exception:
        logged_zones = set()
    for z in zones:
        zid    = z['Id'].split('/')[-1]
        zname  = z['Name']
        is_prv = z.get('Config', {}).get('PrivateZone', False)
        if zid in logged_zones:
            print(f"\033[0;32m[PASS]\033[0m R53-01: Query logging enabled | {zname} (id={zid}) {'[private]' if is_prv else '[public]'}")
        else:
            sev = "WARN" if is_prv else "FAIL"
            color = '1;33' if is_prv else '0;31'
            print(f"\033[{color}m[{sev}]\033[0m R53-01: Query logging DISABLED | {zname} (id={zid}) {'[private]' if is_prv else '[public]'}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m R53-01: {e}")
PYEOF

log "R53-02: Route 53 — DNSSEC signing status on public hosted zones"
python3 - <<'PYEOF'
import boto3
r53 = boto3.client('route53')
try:
    zones = r53.list_hosted_zones()['HostedZones']
    public_zones = [z for z in zones if not z.get('Config', {}).get('PrivateZone', False)]
    if not public_zones:
        print("\033[1;33m[WARN]\033[0m R53-02: No public hosted zones found")
    for z in public_zones:
        zid   = z['Id'].split('/')[-1]
        zname = z['Name']
        try:
            dnssec = r53.get_dnssec(HostedZoneId=zid)
            status = dnssec.get('Status', {}).get('ServeSignature', 'NOT_SIGNING')
            ksks   = dnssec.get('KeySigningKeys', [])
            if status == 'SIGNING':
                print(f"\033[0;32m[PASS]\033[0m R53-02: DNSSEC signing ACTIVE | {zname} | KSKs: {len(ksks)}")
            else:
                print(f"\033[1;33m[WARN]\033[0m R53-02: DNSSEC NOT signing (status={status}) | {zname} — zone susceptible to cache poisoning")
        except Exception as de:
            print(f"\033[1;33m[WARN]\033[0m R53-02: Could not check DNSSEC for '{zname}': {de}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m R53-02: {e}")
PYEOF

log "R53-03: Route 53 — domain transfer lock and auto-renewal"
python3 - <<'PYEOF'
import boto3
r53domains = boto3.client('route53domains', region_name='us-east-1')
try:
    domains = r53domains.list_domains().get('Domains', [])
    if not domains:
        print("\033[1;33m[WARN]\033[0m R53-03: No Route 53 registered domains (may be registered elsewhere)")
    for dom in domains:
        dname = dom['DomainName']
        detail = r53domains.get_domain_detail(DomainName=dname)
        locked    = detail.get('StatusList', [])
        xfer_lock = 'TRANSFER_LOCK' in locked
        auto_renew = detail.get('AutoRenew', False)
        expiry     = detail.get('ExpirationDate', 'N/A')
        print(f"{'\\033[0;32m[PASS]\\033[0m' if xfer_lock else '\\033[0;31m[FAIL]\\033[0m R53-03:'} Transfer lock={'ON' if xfer_lock else 'OFF'} | {dname} (expires: {str(expiry)[:10]})")
        print(f"{'\\033[0;32m[PASS]\\033[0m' if auto_renew else '\\033[1;33m[WARN]\\033[0m'} R53-03: Auto-renew={'ON' if auto_renew else 'OFF'} | {dname}")
except r53domains.exceptions.UnsupportedTLD:
    print("\033[1;33m[WARN]\033[0m R53-03: TLD not supported for domain management via Route 53 Domains API")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m R53-03: Route 53 Domains — {e}")
PYEOF

log "R53-04: Route 53 — health checks configured for critical DNS records"
python3 - <<'PYEOF'
import boto3
r53 = boto3.client('route53')
try:
    checks = r53.list_health_checks()['HealthChecks']
    if not checks:
        print("\033[1;33m[WARN]\033[0m R53-04: No Route 53 health checks configured — failover routing may not function")
    else:
        insecure = []
        for hc in checks:
            hcid = hc['Id']
            cfg  = hc['HealthCheckConfig']
            htype = cfg.get('Type', '')
            port  = cfg.get('Port', 0)
            if htype in ('HTTP',) or port == 80:
                insecure.append(hcid)
            else:
                print(f"\033[0;32m[PASS]\033[0m R53-04: Health check {hcid} type={htype} port={port}")
        for hcid in insecure:
            print(f"\033[1;33m[WARN]\033[0m R53-04: Health check {hcid} uses HTTP (port 80) — consider HTTPS")
        print(f"\033[0;34m[INFO]\033[0m R53-04: Total health checks configured: {len(checks)}")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m R53-04: {e}")
PYEOF

log "R53-05: Route 53 Resolver — DNS firewall and logging"
python3 - <<'PYEOF'
import boto3
r53resolver = boto3.client('route53resolver')
try:
    # DNS Firewall rule groups
    groups = r53resolver.list_firewall_rule_groups().get('FirewallRuleGroups', [])
    assocs = r53resolver.list_firewall_rule_group_associations().get('FirewallRuleGroupAssociations', [])
    if assocs:
        for a in assocs:
            status = a.get('Status', 'N/A')
            print(f"\033[0;32m[PASS]\033[0m R53-05: DNS Firewall rule group associated | {a.get('Name','N/A')} Status={status}")
    else:
        print("\033[1;33m[WARN]\033[0m R53-05: No Route 53 Resolver DNS Firewall associations — DNS exfiltration protection absent")
    # Resolver query logging
    configs = r53resolver.list_resolver_query_log_configs().get('ResolverQueryLogConfigs', [])
    active  = [c for c in configs if c.get('Status') == 'CREATED']
    if active:
        for c in active:
            print(f"\033[0;32m[PASS]\033[0m R53-05: Resolver query logging active | {c['Name']} → {c.get('DestinationArn','N/A').split(':')[-1]}")
    else:
        print("\033[0;31m[FAIL]\033[0m R53-05: Route 53 Resolver query logging NOT configured — DNS activity blind spot")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m R53-05: Resolver checks — {e}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 15: AWS BEDROCK SECURITY
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ AWS BEDROCK SECURITY CHECKS ══${NC}"

log "BDR-01: Bedrock — model invocation logging"
python3 - <<'PYEOF'
import boto3
bedrock = boto3.client('bedrock')
try:
    config = bedrock.get_model_invocation_logging_configuration().get('loggingConfig', {})
    if not config:
        print("\033[0;31m[FAIL]\033[0m BDR-01: Bedrock model invocation logging NOT configured — no audit trail for LLM calls")
    else:
        cw_enabled  = config.get('cloudWatchConfig', {}).get('logGroupName', '')
        s3_enabled  = config.get('s3Config', {}).get('bucketName', '')
        text_log    = config.get('textDataDeliveryEnabled', False)
        image_log   = config.get('imageDataDeliveryEnabled', False)
        embed_log   = config.get('embeddingDataDeliveryEnabled', False)
        if cw_enabled or s3_enabled:
            dest = f"CW={cw_enabled}" if cw_enabled else f"S3={s3_enabled}"
            print(f"\033[0;32m[PASS]\033[0m BDR-01: Invocation logging enabled → {dest}")
            print(f"\033[0;34m[INFO]\033[0m BDR-01: Logging scope — Text={text_log} Image={image_log} Embeddings={embed_log}")
            if not text_log:
                print(f"\033[1;33m[WARN]\033[0m BDR-01: Text data delivery logging is disabled — prompt/response content not captured")
        else:
            print("\033[0;31m[FAIL]\033[0m BDR-01: Invocation logging config present but no destination (CW/S3) configured")
except bedrock.exceptions.AccessDeniedException:
    print("\033[1;33m[WARN]\033[0m BDR-01: Access denied — ensure bedrock:GetModelInvocationLoggingConfiguration permission")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m BDR-01: Bedrock may not be available in this region or {e}")
PYEOF

log "BDR-02: Bedrock — Guardrails configured"
python3 - <<'PYEOF'
import boto3
bedrock = boto3.client('bedrock')
try:
    guardrails = bedrock.list_guardrails().get('guardrails', [])
    if not guardrails:
        print("\033[0;31m[FAIL]\033[0m BDR-02: No Bedrock Guardrails configured — prompt injection, PII, and content risks unmitigated")
    else:
        for g in guardrails:
            gid     = g.get('id', 'N/A')
            gname   = g.get('name', 'N/A')
            gstatus = g.get('status', 'N/A')
            print(f"\033[0;32m[PASS]\033[0m BDR-02: Guardrail '{gname}' (id={gid}) status={gstatus}")
except bedrock.exceptions.AccessDeniedException:
    print("\033[1;33m[WARN]\033[0m BDR-02: Access denied — ensure bedrock:ListGuardrails permission")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m BDR-02: {e}")
PYEOF

log "BDR-03: Bedrock — custom model encryption (KMS)"
python3 - <<'PYEOF'
import boto3
bedrock = boto3.client('bedrock')
try:
    models = bedrock.list_custom_models().get('modelSummaries', [])
    if not models:
        print("\033[0;34m[INFO]\033[0m BDR-03: No custom Bedrock models found")
    else:
        for m in models:
            mname = m.get('modelName', 'N/A')
            marn  = m.get('modelArn', '')
            # Get full model details for KMS key info
            try:
                detail = bedrock.get_custom_model(modelIdentifier=marn)
                kms    = detail.get('modelKmsKeyArn', '')
                print(f"{'\\033[0;32m[PASS]\\033[0m' if kms else '\\033[1;33m[WARN]\\033[0m'} BDR-03: Custom model KMS={'YES: '+kms.split('/')[-1] if kms else 'NOT set (uses AWS-managed)'} | {mname}")
            except Exception:
                print(f"\033[1;33m[WARN]\033[0m BDR-03: Could not get KMS details for model '{mname}'")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m BDR-03: {e}")
PYEOF

log "BDR-04: Bedrock — VPC endpoint (PrivateLink) for data plane isolation"
python3 - <<'PYEOF'
import boto3
ec2 = boto3.client('ec2')
try:
    endpoints = ec2.describe_vpc_endpoints(
        Filters=[{'Name': 'service-name', 'Values': ['*bedrock*']},
                 {'Name': 'vpc-endpoint-state', 'Values': ['available', 'pending']}]
    )['VpcEndpoints']
    if endpoints:
        for ep in endpoints:
            svc = ep['ServiceName'].split('.')[-1]
            print(f"\033[0;32m[PASS]\033[0m BDR-04: Bedrock VPC endpoint present | {ep['VpcEndpointId']} svc={svc}")
    else:
        print("\033[1;33m[WARN]\033[0m BDR-04: No Bedrock VPC endpoints — traffic traverses public internet; consider PrivateLink for data isolation")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m BDR-04: {e}")
PYEOF

log "BDR-05: Bedrock — IAM permissions for model access (least privilege check)"
python3 - <<'PYEOF'
import boto3, json
iam = boto3.client('iam')
try:
    # Look for any policy allowing bedrock:* or bedrock:InvokeModel with Resource:*
    paginator = iam.get_paginator('list_policies')
    found_issues = False
    for page in paginator.paginate(Scope='Local'):
        for policy in page['Policies']:
            parn = policy['Arn']
            vid  = policy['DefaultVersionId']
            try:
                doc = iam.get_policy_version(PolicyArn=parn, VersionId=vid)['PolicyVersion']['Document']
                for stmt in doc.get('Statement', []):
                    if stmt.get('Effect') != 'Allow': continue
                    actions = stmt.get('Action', [])
                    resource = stmt.get('Resource', '')
                    if isinstance(actions, str): actions = [actions]
                    bedrock_wild = any(a in ('bedrock:*', '*') for a in actions)
                    broad_invoke = any(a == 'bedrock:InvokeModel' for a in actions) and resource == '*'
                    if bedrock_wild or broad_invoke:
                        print(f"\033[1;33m[WARN]\033[0m BDR-05: Overly broad Bedrock permission in policy '{policy['PolicyName']}' Action={actions} Resource={resource}")
                        found_issues = True
            except Exception:
                pass
    if not found_issues:
        print("\033[0;32m[PASS]\033[0m BDR-05: No wildcard Bedrock permissions found in customer-managed policies")
except Exception as e:
    print(f"\033[0;31m[FAIL]\033[0m BDR-05: {e}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 16: AWS BEDROCK AGENT CORE SECURITY
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${BLUE}══ AWS BEDROCK AGENT CORE SECURITY CHECKS ══${NC}"

log "AGT-01: Bedrock Agents — resource encryption (KMS)"
python3 - <<'PYEOF'
import boto3
bedrock_agent = boto3.client('bedrock-agent')
try:
    agents = bedrock_agent.list_agents().get('agentSummaries', [])
    if not agents:
        print("\033[0;34m[INFO]\033[0m AGT-01: No Bedrock Agents found in this region")
    for a in agents:
        aid   = a['agentId']
        aname = a.get('agentName', aid)
        try:
            detail = bedrock_agent.get_agent(agentId=aid)['agent']
            kms    = detail.get('customerEncryptionKeyArn', '')
            status = detail.get('agentStatus', 'N/A')
            print(f"{'\\033[0;32m[PASS]\\033[0m' if kms else '\\033[1;33m[WARN]\\033[0m'} AGT-01: KMS={'CUSTOMER: '+kms.split('/')[-1] if kms else 'AWS-managed'} Status={status} | {aname}")
        except Exception as de:
            print(f"\033[1;33m[WARN]\033[0m AGT-01: Could not get details for agent '{aname}': {de}")
except bedrock_agent.exceptions.AccessDeniedException:
    print("\033[1;33m[WARN]\033[0m AGT-01: Access denied — ensure bedrock:ListAgents permission")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m AGT-01: Bedrock Agents may not be available in this region | {e}")
PYEOF

log "AGT-02: Bedrock Agents — IAM execution role least privilege"
python3 - <<'PYEOF'
import boto3, json
bedrock_agent = boto3.client('bedrock-agent')
iam = boto3.client('iam')
try:
    agents = bedrock_agent.list_agents().get('agentSummaries', [])
    for a in agents:
        aid   = a['agentId']
        aname = a.get('agentName', aid)
        try:
            detail   = bedrock_agent.get_agent(agentId=aid)['agent']
            role_arn = detail.get('agentResourceRoleArn', '')
            if not role_arn:
                print(f"\033[0;31m[FAIL]\033[0m AGT-02: No execution role found for agent '{aname}'")
                continue
            role_name = role_arn.split('/')[-1]
            # Check inline policies for wildcard
            inline = iam.list_role_policies(RoleName=role_name).get('PolicyNames', [])
            for pname in inline:
                doc = iam.get_role_policy(RoleName=role_name, PolicyName=pname)['PolicyDocument']
                for stmt in doc.get('Statement', []):
                    if stmt.get('Effect') == 'Allow':
                        actions   = stmt.get('Action', [])
                        resource  = stmt.get('Resource', '')
                        if isinstance(actions, str): actions = [actions]
                        if '*' in actions or ('*' == resource and any('bedrock' in str(a) for a in actions)):
                            print(f"\033[1;33m[WARN]\033[0m AGT-02: Agent '{aname}' role '{role_name}' inline policy '{pname}' has broad permissions")
            print(f"\033[0;32m[PASS]\033[0m AGT-02: Agent '{aname}' uses role '{role_name}'")
        except Exception as de:
            print(f"\033[1;33m[WARN]\033[0m AGT-02: Could not audit role for agent '{aname}': {de}")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m AGT-02: {e}")
PYEOF

log "AGT-03: Bedrock Agent — Knowledge Bases encryption and data source security"
python3 - <<'PYEOF'
import boto3
bedrock_agent = boto3.client('bedrock-agent')
try:
    kbs = bedrock_agent.list_knowledge_bases().get('knowledgeBaseSummaries', [])
    if not kbs:
        print("\033[0;34m[INFO]\033[0m AGT-03: No Bedrock Knowledge Bases found")
    for kb in kbs:
        kbid   = kb['knowledgeBaseId']
        kbname = kb.get('name', kbid)
        status = kb.get('status', 'N/A')
        try:
            detail = bedrock_agent.get_knowledge_base(knowledgeBaseId=kbid)['knowledgeBase']
            kms    = detail.get('serverSideEncryptionConfiguration', {}).get('kmsKeyArn', '')
            print(f"{'\\033[0;32m[PASS]\\033[0m' if kms else '\\033[1;33m[WARN]\\033[0m'} AGT-03: KB '{kbname}' KMS={'SET' if kms else 'AWS-managed'} Status={status}")
            # Check data sources
            sources = bedrock_agent.list_data_sources(knowledgeBaseId=kbid).get('dataSourceSummaries', [])
            for ds in sources:
                dsid     = ds['dataSourceId']
                dsname   = ds.get('name', dsid)
                dsstatus = ds.get('status', 'N/A')
                ds_detail = bedrock_agent.get_data_source(knowledgeBaseId=kbid, dataSourceId=dsid)['dataSource']
                ds_kms    = ds_detail.get('serverSideEncryptionConfiguration', {}).get('kmsKeyArn', '')
                print(f"  {'\\033[0;32m[PASS]\\033[0m' if ds_kms else '\\033[1;33m[WARN]\\033[0m'}   AGT-03: DataSource '{dsname}' KMS={'SET' if ds_kms else 'not set'} Status={dsstatus}")
        except Exception as de:
            print(f"\033[1;33m[WARN]\033[0m AGT-03: Could not get details for KB '{kbname}': {de}")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m AGT-03: {e}")
PYEOF

log "AGT-04: Bedrock Agent — Action Group Lambda function security"
python3 - <<'PYEOF'
import boto3
bedrock_agent = boto3.client('bedrock-agent')
lmb = boto3.client('lambda')
try:
    agents = bedrock_agent.list_agents().get('agentSummaries', [])
    for a in agents:
        aid   = a['agentId']
        aname = a.get('agentName', aid)
        try:
            groups = bedrock_agent.list_agent_action_groups(
                agentId=aid, agentVersion='DRAFT'
            ).get('actionGroupSummaries', [])
            for grp in groups:
                gname = grp.get('actionGroupName', 'N/A')
                gid   = grp.get('actionGroupId', '')
                detail = bedrock_agent.get_agent_action_group(
                    agentId=aid, agentVersion='DRAFT', actionGroupId=gid
                )['agentActionGroup']
                executor = detail.get('actionGroupExecutor', {})
                lambda_arn = executor.get('lambda', '')
                if lambda_arn:
                    fn_name = lambda_arn.split(':')[-1]
                    # Check Lambda resource policy for overly broad invoke permissions
                    try:
                        policy = lmb.get_policy(FunctionName=fn_name)['Policy']
                        import json
                        doc = json.loads(policy)
                        for stmt in doc.get('Statement', []):
                            principal = stmt.get('Principal', {})
                            p_val = principal if isinstance(principal, str) else str(principal)
                            if stmt.get('Effect') == 'Allow' and '*' in p_val:
                                print(f"\033[0;31m[FAIL]\033[0m AGT-04: Lambda '{fn_name}' for action group '{gname}' has wildcard invoke principal")
                            else:
                                print(f"\033[0;32m[PASS]\033[0m AGT-04: Lambda '{fn_name}' resource policy scoped | agent: {aname} group: {gname}")
                    except lmb.exceptions.ResourceNotFoundException:
                        print(f"\033[0;32m[PASS]\033[0m AGT-04: Lambda '{fn_name}' has no resource policy (IAM-only access) | {gname}")
        except Exception as age:
            print(f"\033[1;33m[WARN]\033[0m AGT-04: Could not audit action groups for agent '{aname}': {age}")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m AGT-04: {e}")
PYEOF

log "AGT-05: Bedrock Agent — prompt injection & session isolation controls"
python3 - <<'PYEOF'
import boto3
bedrock_agent = boto3.client('bedrock-agent')
bedrock       = boto3.client('bedrock')
try:
    agents = bedrock_agent.list_agents().get('agentSummaries', [])
    # Check that guardrails are applied at agent level
    guardrails = {g['id'] for g in bedrock.list_guardrails().get('guardrails', [])}
    for a in agents:
        aid   = a['agentId']
        aname = a.get('agentName', aid)
        try:
            detail = bedrock_agent.get_agent(agentId=aid)['agent']
            grail  = detail.get('guardrailConfiguration', {}).get('guardrailIdentifier', '')
            if grail:
                print(f"\033[0;32m[PASS]\033[0m AGT-05: Guardrail applied to agent '{aname}' (id={grail})")
            else:
                print(f"\033[0;31m[FAIL]\033[0m AGT-05: No Guardrail on agent '{aname}' — prompt injection and content policy risks unmitigated")
            # Idle session timeout
            session_ttl = detail.get('idleSessionTTLInSeconds', 0)
            if session_ttl > 3600:
                print(f"\033[1;33m[WARN]\033[0m AGT-05: Session TTL={session_ttl}s (>{3600}s) on agent '{aname}' — long session windows increase hijack risk")
            else:
                print(f"\033[0;32m[PASS]\033[0m AGT-05: Session TTL={session_ttl}s | {aname}")
        except Exception as de:
            print(f"\033[1;33m[WARN]\033[0m AGT-05: {de}")
except Exception as e:
    print(f"\033[1;33m[WARN]\033[0m AGT-05: {e}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY & EVIDENCE MANIFEST
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "======================================================================"
echo -e " ${GREEN}PASS${NC}: $PASS  |  ${RED}FAIL${NC}: $FAIL  |  ${YELLOW}WARN${NC}: $WARN"
echo " Total checks : $((PASS + FAIL + WARN))"
echo " Evidence saved: $OUTPUT_DIR/"
echo "======================================================================"
echo ""

# Generate evidence manifest
MANIFEST="$OUTPUT_DIR/AUDIT_MANIFEST.txt"
{
  echo "AWS Security Audit Evidence Manifest"
  echo "====================================="
  echo "Account  : $ACCOUNT"
  echo "Region   : $REGION"
  echo "Run Time : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo ""
  echo "Results Summary"
  echo "  PASS : $PASS"
  echo "  FAIL : $FAIL"
  echo "  WARN : $WARN"
  echo "  Total: $((PASS + FAIL + WARN))"
  echo ""
  echo "Service Domains Audited"
  echo "  1.  IAM (Identity & Access Management)"
  echo "  2.  S3 (Simple Storage Service)"
  echo "  3.  VPC / Network Security"
  echo "  4.  Logging & Monitoring (CloudTrail, Config, GuardDuty, Security Hub)"
  echo "  5.  Encryption & KMS"
  echo "  6.  Compute / EC2"
  echo "  7.  Containers (ECR)"
  echo "  8.  Backup & DR"
  echo "  9.  Amazon RDS"
  echo "  10. Amazon S3 Glacier"
  echo "  11. Amazon SNS"
  echo "  12. Amazon SQS"
  echo "  13. Amazon CloudFront"
  echo "  14. Amazon Route 53"
  echo "  15. AWS Bedrock"
  echo "  16. AWS Bedrock Agent Core"
  echo ""
  echo "Evidence Files"
  ls -1 "$OUTPUT_DIR/" 2>/dev/null | grep -v AUDIT_MANIFEST | while read f; do
    echo "  - $f"
  done
} > "$MANIFEST"

echo -e " Evidence manifest written: ${BLUE}$MANIFEST${NC}"
echo ""
