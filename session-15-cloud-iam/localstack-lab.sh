#!/usr/bin/env bash
# localstack-lab.sh — cloud practice without a credit card, or a bill
#
#   ./localstack-lab.sh up                     start LocalStack, configure the CLI
#   ./localstack-lab.sh bucket <name>          create one, then interrogate it
#   ./localstack-lab.sh posture <bucket>       the four questions, answered
#   ./localstack-lab.sh harden <bucket>        answer them properly
#   ./localstack-lab.sh policy-lab             the reduction exercise, guided
#   ./localstack-lab.sh negative <bucket>      prove something is now denied
#   ./localstack-lab.sh down
#
# The four questions belong to ANY storage resource in ANY provider:
#   1. Can the public reach it?
#   2. Is it encrypted, and who holds the key?
#   3. Is versioning on?   (this is a ransomware control)
#   4. Is access logged?   (data-plane, not just management-plane)

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"

ENDPOINT="${AWS_ENDPOINT_URL:-http://localhost:4566}"
NAME="${LS_NAME:-blueteam-localstack}"
awsl() { aws --endpoint-url="$ENDPOINT" "$@"; }

usage() { sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

cmd_up() {
  need docker || exit 1
  need aws "pip install awscli" || exit 1
  banner "LocalStack" "no account, no credit card, no bill at the end of the month"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  docker run -d --name "$NAME" -p 4566:4566 localstack/localstack >/dev/null || die "docker run failed"
  # Fake credentials, because LocalStack does not check them. Setting them stops
  # the CLI from silently falling back to your REAL profile, which is the failure
  # mode that turns a lab exercise into a live API call.
  aws configure set aws_access_key_id test
  aws configure set aws_secret_access_key test
  aws configure set region eu-west-1
  info "waiting"
  for i in $(seq 1 30); do
    awsl s3 ls >/dev/null 2>&1 && { say ""; ok "ready at $ENDPOINT"; break; }
    printf '.'; sleep 2
    [[ $i -eq 30 ]] && { say ""; die "LocalStack did not come up — docker logs $NAME"; }
  done
  hint "alias awsl='aws --endpoint-url=$ENDPOINT'   — you will type it forty times"
}

cmd_bucket() {
  local b="${1:-blueteam-lab-data}"
  need aws || exit 1
  awsl s3 mb "s3://$b" 2>/dev/null && ok "created s3://$b" || warn "already exists"
  echo "sample object $(utc)" > /tmp/sample.txt
  awsl s3 cp /tmp/sample.txt "s3://$b/uploads/sample.txt" >/dev/null && ok "uploaded uploads/sample.txt"
  say ""
  cmd_posture "$b"
}

cmd_posture() {
  local b="${1:-}"; [[ -n "$b" ]] || die "usage: $0 posture <bucket>"
  need aws || exit 1
  banner "Posture: $b" "the four questions, for any storage in any provider"
  local n=0

  info "1. can the public reach it?"
  local pab; pab=$(awsl s3api get-public-access-block --bucket "$b" 2>/dev/null || true)
  if [[ -z "$pab" ]]; then
    bad "no public access block configured"; n=$((n+1))
    hint "block it at the ACCOUNT level, not per bucket — per-bucket is a decision"
    hint "somebody gets to make wrong, once, at 23h00"
  else
    echo "$pab" | sed 's/^/     /'
    echo "$pab" | grep -q 'false' && { bad "at least one setting is false"; n=$((n+1)); } || ok "fully blocked"
  fi

  info "2. is it encrypted, and who holds the key?"
  local enc; enc=$(awsl s3api get-bucket-encryption --bucket "$b" 2>/dev/null || true)
  if [[ -z "$enc" ]]; then
    bad "no default encryption"; n=$((n+1))
  else
    echo "$enc" | sed 's/^/     /'
    echo "$enc" | grep -q 'aws:kms' \
      && ok "KMS — now ask WHICH key, and who can use it" \
      || { warn "provider-managed key (AES256)"
           hint "fine for most things. Not fine when the requirement says you hold the key."; }
  fi

  info "3. is versioning on?"
  local ver; ver=$(awsl s3api get-bucket-versioning --bucket "$b" 2>/dev/null | grep -o 'Enabled' || true)
  if [[ "$ver" == "Enabled" ]]; then ok "enabled"
  else bad "not enabled"; n=$((n+1))
       hint "this is a ransomware control: an overwrite is recoverable, a delete is a marker"; fi

  info "4. is access logged?"
  local log; log=$(awsl s3api get-bucket-logging --bucket "$b" 2>/dev/null | grep -o 'TargetBucket' || true)
  if [[ -n "$log" ]]; then ok "server access logging configured"
  else
    bad "no access logging"; n=$((n+1))
    hint "and note: this is the management plane. DATA-plane events — who READ"
    hint "which object — are a separate setting, usually off, and separately billed."
    hint "an attacker who reads ten thousand objects generates one event, or none."
  fi

  say ""
  [[ $n -eq 0 ]] && ok "all four answered well" || { bad "$n of 4 unanswered"; hint "fix: $0 harden $b"; }
}

cmd_harden() {
  local b="${1:-}"; [[ -n "$b" ]] || die "usage: $0 harden <bucket>"
  need aws || exit 1
  banner "Hardening $b"
  awsl s3api put-public-access-block --bucket "$b" --public-access-block-configuration \
    'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true' \
    >/dev/null 2>&1 && ok "public access blocked" || warn "could not set public access block"
  awsl s3api put-bucket-encryption --bucket "$b" --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
    >/dev/null 2>&1 && ok "default encryption" || warn "could not set encryption"
  awsl s3api put-bucket-versioning --bucket "$b" --versioning-configuration Status=Enabled \
    >/dev/null 2>&1 && ok "versioning" || warn "could not enable versioning"
  say ""
  cmd_posture "$b"
}

cmd_policy_lab() {
  banner "The reduction exercise" "start broad, shrink until only the task works"
  cat <<'LAB'

  Start here. This is every permission, on everything:

    { "Effect": "Allow", "Action": "s3:*", "Resource": "*" }

  Now reduce, ONE step at a time, testing after each:

    s3:*          on *                  everything, everywhere
    s3:*          on this bucket        scoped to one resource
    Get/Put/List  on this bucket        scoped to needed actions
    Get/Put       on bucket/uploads/*   scoped to a path
    + Condition:  TLS required          scoped by circumstance
    + Condition:  source VPC endpoint   scoped by network path

  The finished article:

    {
      "Version": "2012-10-17",
      "Statement": [{
        "Sid": "AppUploadsOnly",
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:PutObject"],
        "Resource": "arn:aws:s3:::blueteam-lab-data/uploads/*",
        "Condition": {
          "Bool":         { "aws:SecureTransport": "true" },
          "StringEquals": { "s3:x-amz-server-side-encryption": "AES256" }
        }
      }]
    }

  Two things people get wrong:

  RESOURCE IS THE BUCKET, OR THE OBJECTS, AND THEY ARE DIFFERENT ARNS.
    arn:aws:s3:::bucket        the bucket itself   (ListBucket lives here)
    arn:aws:s3:::bucket/*      the objects in it   (GetObject lives here)
    A policy that lists one and not the other fails in a way that looks like
    a permissions bug and is actually a reading-comprehension bug.

  TEST AFTER EVERY REDUCTION, AND TEST THE NEGATIVE.
    The task must still work, AND one thing outside the task must now fail.
    A reduction you did not test is a guess with better formatting.
    Prove it:  ./localstack-lab.sh negative <bucket>

LAB
}

cmd_negative() {
  local b="${1:-}"; [[ -n "$b" ]] || die "usage: $0 negative <bucket>"
  need aws || exit 1
  banner "The negative test" "the half of the exercise everyone skips"
  say ""
  say "  A policy reduction is proven by TWO results, not one:"
  say "    1. the intended task still works"
  say "    2. something outside the task now fails"
  say ""

  info "positive: read an object from uploads/"
  if awsl s3 cp "s3://$b/uploads/sample.txt" /tmp/neg-test.txt >/dev/null 2>&1; then
    ok "allowed, as intended"
  else
    bad "denied — the policy is now too tight, or the object is not there"
  fi

  info "negative: read from a different prefix"
  echo x > /tmp/x.txt
  awsl s3 cp /tmp/x.txt "s3://$b/secret/x.txt" >/dev/null 2>&1 || true
  if awsl s3 cp "s3://$b/secret/x.txt" /tmp/neg2.txt >/dev/null 2>&1; then
    warn "STILL ALLOWED — the reduction has not taken effect"
    hint "LocalStack does not enforce IAM the way the real thing does. On a real"
    hint "account, this is where you would see the AccessDenied. Note the limitation"
    hint "in your write-up — 'tested against LocalStack' is an honest methodology line."
  else
    ok "denied — that is the proof"
  fi
  say ""
  hint "record both results. One without the other proves nothing."
}

cmd_down() { need docker || exit 1; docker rm -f "$NAME" >/dev/null 2>&1 && ok "stopped" || warn "not running"; }

case "${1:-}" in
  up)         shift; cmd_up "$@" ;;
  bucket)     shift; cmd_bucket "$@" ;;
  posture)    shift; cmd_posture "$@" ;;
  harden)     shift; cmd_harden "$@" ;;
  policy-lab) shift; cmd_policy_lab "$@" ;;
  negative)   shift; cmd_negative "$@" ;;
  down)       shift; cmd_down "$@" ;;
  ''|-h|--help|help) usage 0 ;;
  *) bad "unknown command: $1"; usage 1 ;;
esac
