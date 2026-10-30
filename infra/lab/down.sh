#!/usr/bin/env bash
# Remove the scanner lab, then prove it is gone. You run this.
#
#   infra/lab/down.sh <aws-profile> <region> <sandbox-account-id>
#
# 1. empties the lab buckets (a non-empty bucket blocks the stack delete)
# 2. deletes the stack and waits
# 3. switches Inspector EC2 off, only if up.sh switched it on
# 4. checks, read-only, that nothing is left: no stack, no tagged resource, no lab IAM
#    role or user, Inspector back to its earlier state. Exits 1 and lists any leftover.
set -euo pipefail

PROFILE=${1:?aws profile}; REGION=${2:?region}; CONFIRM=${3:?sandbox account id}
STACK=${LAB_STACK:-scanner-lab}
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd); OUT="$ROOT/reports/lab"
aws() { command aws --profile "$PROFILE" --region "$REGION" "$@"; }

ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
if [[ "$ACCOUNT" != "$CONFIRM" ]]; then
  echo "refusing: profile $PROFILE is account $ACCOUNT, not $CONFIRM" >&2; exit 2
fi
ctx() { python3 -c "import json,sys; print(json.load(open('$OUT/lab-context.json')).get('$1',''))" 2>/dev/null || true; }

# 1. empty the buckets
for b in $(aws cloudformation describe-stacks --stack-name "$STACK" \
             --query "Stacks[0].Outputs[?OutputKey=='PublicBucket'||OutputKey=='PrivateBucket'].OutputValue" \
             --output text 2>/dev/null || true); do
  aws s3 rm "s3://$b" --recursive --quiet || true
done

# 2. delete the stack
if aws cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1; then
  echo "deleting $STACK (a few minutes)"
  aws cloudformation delete-stack --stack-name "$STACK"
  aws cloudformation wait stack-delete-complete --stack-name "$STACK"
fi

# 3. Inspector back to how it was
if [[ "$(ctx inspector_enabled_by_lab)" == "True" ]]; then
  aws inspector2 disable --resource-types EC2 >/dev/null
  echo "Inspector EC2 scanning switched off (up.sh had switched it on)"
fi

# 4. prove it
left=0
if aws cloudformation describe-stacks --stack-name "$STACK" >/dev/null 2>&1; then
  echo "LEFT: stack $STACK still exists"; left=1
fi
# The tagging index keeps deleted resources for a while (seen 2026-10-29: terminated
# instances, deleted volumes and endpoints, 20+ minutes after the stack delete), so each
# tagged ARN is asked of EC2 itself. A type not handled here counts as left.
gone() {
  local id=${1##*/} state
  case "$1" in
    *:instance/*) state=$(aws ec2 describe-instances --instance-ids "$id" \
                    --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || true)
                  [[ "$state" == terminated || -z "$state" ]] ;;
    *:volume/*)       ! aws ec2 describe-volumes --volume-ids "$id" >/dev/null 2>&1 ;;
    *:vpc-endpoint/*) [[ -z "$(aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$id" \
                     --query 'VpcEndpoints[?State!=`deleted`].VpcEndpointId' --output text 2>/dev/null)" ]] ;;
    *:vpc/*)          ! aws ec2 describe-vpcs --vpc-ids "$id" >/dev/null 2>&1 ;;
    *:subnet/*)       ! aws ec2 describe-subnets --subnet-ids "$id" >/dev/null 2>&1 ;;
    *:security-group/*) ! aws ec2 describe-security-groups --group-ids "$id" >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}
for arn in $(aws resourcegroupstaggingapi get-resources --tag-filters Key=scanner-lab \
               --query 'ResourceTagMappingList[].ResourceARN' --output text); do
  if gone "$arn"; then echo "gone (tag index is stale): $arn"; else echo "LEFT: $arn"; left=1; fi
done
for r in escalator instance-min function-min ext-trust ext-trust-ok; do
  if aws iam get-role --role-name "$STACK-$r" >/dev/null 2>&1; then echo "LEFT: role $STACK-$r"; left=1; fi
done
for u in nomfa noconsole leaked-key; do
  if aws iam get-user --user-name "$STACK-$u" >/dev/null 2>&1; then echo "LEFT: user $STACK-$u"; left=1; fi
done
for g in open-fn iam-fn; do
  n=$(aws logs describe-log-groups --log-group-name-prefix "/aws/lambda/$STACK-$g" \
        --query 'length(logGroups)' --output text)
  if [[ "$n" != "0" ]]; then echo "LEFT: log group /aws/lambda/$STACK-$g"; left=1; fi
done
now=$(aws inspector2 batch-get-account-status --account-ids "$ACCOUNT" \
        --query 'accounts[0].resourceState.ec2.status' --output text 2>/dev/null || echo UNKNOWN)
before=$(ctx inspector_ec2_before)
echo "Inspector EC2: now $now, before the lab ${before:-unknown}"

stamp=$(date -u +%FT%TZ)
if [[ $left == 0 ]]; then echo "CLEAN at $stamp: nothing from $STACK is left in $ACCOUNT/$REGION"; exit 0; fi
echo "NOT CLEAN at $stamp: see LEFT lines above"; exit 1
