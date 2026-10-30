#!/usr/bin/env bash
# Deploy the scanner lab into a SANDBOX account. You run this; the scanner never does.
#
#   infra/lab/up.sh <aws-profile> <region> <sandbox-account-id> <external-account-id> [--tier2]
#
# <sandbox-account-id> must equal the profile's account, so a wrong profile stops here.
# <external-account-id> is another account of yours; two permission-less roles trust it.
# --tier2 also switches Inspector on for EC2 (only if it is off; down.sh switches it back off).
#
# Writes reports/lab/outputs.json and reports/lab/lab-context.json (reports/ is gitignored).
set -euo pipefail

PROFILE=${1:?aws profile}; REGION=${2:?region}; CONFIRM=${3:?sandbox account id}
EXTERNAL=${4:?external account id}; TIER2=${5:-}
STACK=${LAB_STACK:-scanner-lab}
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd); OUT="$ROOT/reports/lab"
aws() { command aws --profile "$PROFILE" --region "$REGION" "$@"; }

ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
if [[ "$ACCOUNT" != "$CONFIRM" ]]; then
  echo "refusing: profile $PROFILE is account $ACCOUNT, not $CONFIRM" >&2; exit 2
fi
if [[ "$EXTERNAL" == "$ACCOUNT" ]]; then
  echo "refusing: the external account must be a different account" >&2; exit 2
fi

# Preflight, reads only. A public bucket can't be created under account-level Block Public
# Access; that setting is yours, so the lab stops rather than changing it.
BPA=$(aws s3control get-public-access-block --account-id "$ACCOUNT" \
        --query 'PublicAccessBlockConfiguration.BlockPublicPolicy' --output text 2>/dev/null || echo False)
if [[ "$BPA" == "True" ]]; then
  echo "refusing: account-level S3 Block Public Access is on; the lab's public bucket can't exist." >&2
  echo "Turn it off in this sandbox yourself if you want that check scored, then re-run." >&2; exit 3
fi
EBS_DEFAULT=$(aws ec2 get-ebs-encryption-by-default --query EbsEncryptionByDefault --output text)
INSPECTOR_EC2=$(aws inspector2 batch-get-account-status --account-ids "$ACCOUNT" \
        --query 'accounts[0].resourceState.ec2.status' --output text 2>/dev/null || echo UNKNOWN)

# Fake secrets in real formats, made fresh each deploy so none lives in the repo.
read -r OPENAI GITHUB PASSWORD < <(python3 - <<'EOF'
import secrets, string
a = string.ascii_letters + string.digits
r = lambda n: "".join(secrets.choice(a) for _ in range(n))
print("sk-proj-" + r(24) + "T3BlbkFJ" + r(24), "ghp_" + r(36), r(24) + "Aa1!")
EOF
)

echo "deploying $STACK to account $ACCOUNT in $REGION (about 5 minutes)"
aws cloudformation deploy --stack-name "$STACK" --template-file "$HERE/scanner-lab.yaml" \
  --capabilities CAPABILITY_NAMED_IAM --tags scanner-lab=1 --no-fail-on-empty-changeset \
  --parameter-overrides ExternalAccountId="$EXTERNAL" FakeOpenAiKey="$OPENAI" \
    FakeGithubToken="$GITHUB" ConsolePassword="$PASSWORD"

mkdir -p "$OUT"
aws cloudformation describe-stacks --stack-name "$STACK" --query 'Stacks[0].Outputs' --output json |
  python3 -c 'import json,sys; print(json.dumps({o["OutputKey"]: o["OutputValue"] for o in json.load(sys.stdin)}, indent=2))' \
  > "$OUT/outputs.json"

ENABLED_BY_LAB=false
if [[ "$TIER2" == "--tier2" && "$INSPECTOR_EC2" != "ENABLED" ]]; then
  aws inspector2 enable --resource-types EC2 >/dev/null
  ENABLED_BY_LAB=true
  echo "Inspector EC2 scanning switched on (down.sh switches it off again)"
fi

python3 - "$OUT/lab-context.json" <<EOF
import json, sys
json.dump({"stack": "$STACK", "region": "$REGION", "account": "$ACCOUNT",
           "ebs_encryption_by_default": "$EBS_DEFAULT" == "True",
           "inspector_ec2_before": "$INSPECTOR_EC2",
           "inspector_enabled_by_lab": $( [[ $ENABLED_BY_LAB == true ]] && echo True || echo False )},
          open(sys.argv[1], "w"), indent=2)
EOF

cat <<EOF

Lab is up. Outputs: $OUT/outputs.json
Next (tier 2 needs 15-30 minutes for SSM inventory, the patch scan and Inspector):
  cloudtools security scan --aws-profile $PROFILE --region $REGION --regions $REGION --tier 2 --out $OUT
  python3 tools/lab_score.py --report $OUT/runs/<run_id>/report.json \\
      --outputs $OUT/outputs.json --context $OUT/lab-context.json
Remove it:
  infra/lab/down.sh $PROFILE $REGION $ACCOUNT
EOF
