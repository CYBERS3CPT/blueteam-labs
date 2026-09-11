#!/usr/bin/env bash
# teardown-check.sh — prove the lab is gone, in every region, including the
# things that survive `terraform destroy`
#
# Teardown is not optional and it is not homework. A lab that outlives its
# purpose is shadow infrastructure, and a forgotten lab credential is a real
# credential — Session 16's attack pattern 2 does not care that the account was
# "just a lab".
#
#   ./teardown-check.sh terraform [dir]   destroy, then prove the state is empty
#   ./teardown-check.sh sweep             the survivors, across every region
#   ./teardown-check.sh checklist         the full list, for the report
#   ./teardown-check.sh all
#
# Set AWS_ENDPOINT_URL to point at LocalStack. Without it, this talks to a real
# account — which is either exactly what you want, or exactly what you do not.

. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/common.sh"
set +o errexit

AWSX=(aws)
[[ -n "${AWS_ENDPOINT_URL:-}" ]] && AWSX=(aws --endpoint-url="$AWS_ENDPOINT_URL")

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

cmd_terraform() {
  local dir="${1:-.}"
  need terraform || exit 1
  banner "Terraform teardown" "$dir"
  [[ -d "$dir/.terraform" || -f "$dir/terraform.tfstate" ]] || \
    warn "no terraform state in $dir — are you in the right directory?"

  ( cd "$dir" || exit 1
    info "what would go"
    terraform plan -destroy -no-color 2>/dev/null | tail -20 | sed 's/^/  /'
    say ""
    confirm "destroy everything above?" || { warn "not destroyed — the lab is still running and still costing"; exit 0; }
    terraform destroy -auto-approve -no-color | tail -12 | sed 's/^/  /'
    say ""
    info "state must now be empty"
    local left; left=$(terraform state list 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$left" -eq 0 ]]; then
      ok "0 resources in state"
    else
      bad "$left resource(s) still in state:"
      terraform state list | sed 's/^/     /'
      hint "a resource left in state is usually one that failed to delete, not one"
      hint "terraform forgot. Look at why before you remove it from state."
    fi )
  say ""
  warn "state empty is NOT the same as account empty"
  hint "terraform only knows what it created. Now: $0 sweep"
}

cmd_sweep() {
  need aws "pip install awscli" || exit 1
  banner "Sweep" "the things that survive a destroy, in every region"

  local regions
  regions=$("${AWSX[@]}" ec2 describe-regions --query 'Regions[].RegionName' --output text 2>/dev/null) \
    || regions="eu-west-1 eu-west-2 eu-central-1 us-east-1 us-west-2"
  info "checking $(wc -w <<< "$regions" | tr -d ' ') region(s)"
  hint "every region. The forgotten instance is never in the one you deployed to."

  local total=0
  for r in $regions; do
    local found=""
    # Snapshots, images and volumes outlive the instance they came from. This is
    # the number one survivor, every time.
    local n
    n=$("${AWSX[@]}" ec2 describe-snapshots --owner-ids self --region "$r" \
        --query 'length(Snapshots)' --output text 2>/dev/null) || n=0
    [[ "$n" =~ ^[0-9]+$ && "$n" -gt 0 ]] && found+="  snapshots: $n\n"
    n=$("${AWSX[@]}" ec2 describe-images --owners self --region "$r" \
        --query 'length(Images)' --output text 2>/dev/null) || n=0
    [[ "$n" =~ ^[0-9]+$ && "$n" -gt 0 ]] && found+="  AMIs: $n\n"
    n=$("${AWSX[@]}" ec2 describe-volumes --region "$r" \
        --query 'length(Volumes)' --output text 2>/dev/null) || n=0
    [[ "$n" =~ ^[0-9]+$ && "$n" -gt 0 ]] && found+="  volumes: $n\n"
    n=$("${AWSX[@]}" ec2 describe-instances --region "$r" \
        --query 'length(Reservations[].Instances[?State.Name!=`terminated`][])' --output text 2>/dev/null) || n=0
    [[ "$n" =~ ^[0-9]+$ && "$n" -gt 0 ]] && found+="  instances: $n\n"

    if [[ -n "$found" ]]; then
      warn "$r"
      printf "$found" | sed 's/^/   /'
      total=$((total+1))
    fi
  done
  [[ $total -eq 0 ]] && ok "no compute survivors in any region"

  say ""
  info "S3 (global)"
  local buckets; buckets=$("${AWSX[@]}" s3api list-buckets --query 'Buckets[].Name' --output text 2>/dev/null)
  if [[ -n "$buckets" ]]; then
    for b in $buckets; do
      local v; v=$("${AWSX[@]}" s3api get-bucket-versioning --bucket "$b" --query Status --output text 2>/dev/null)
      if [[ "$v" == "Enabled" ]]; then
        warn "$b  (versioning ON)"
        hint "delete markers are not deletion. An 'empty' versioned bucket still holds every object."
      else
        warn "$b"
      fi
    done
  else ok "no buckets"; fi

  say ""
  info "IAM — access keys and roles created during the exercise"
  "${AWSX[@]}" iam list-users --query 'Users[].UserName' --output text 2>/dev/null | tr '\t' '\n' | while read -r u; do
    [[ -z "$u" ]] && continue
    local k; k=$("${AWSX[@]}" iam list-access-keys --user-name "$u" --query 'length(AccessKeyMetadata)' --output text 2>/dev/null)
    [[ "$k" =~ ^[0-9]+$ && "$k" -gt 0 ]] && warn "user $u has $k access key(s)"
  done
  local roles; roles=$("${AWSX[@]}" iam list-roles --query 'Roles[?!starts_with(RoleName, `AWSService`)].RoleName' --output text 2>/dev/null)
  [[ -n "$roles" ]] && { warn "roles present:"; tr '\t' '\n' <<< "$roles" | sed 's/^/     /' | head -15; }

  say ""
  info "anything shared with an external account"
  hint "this is the one that is not a cost problem — it is a data problem"
  "${AWSX[@]}" ec2 describe-snapshots --owner-ids self --query 'Snapshots[].SnapshotId' --output text 2>/dev/null \
    | tr '\t' '\n' | head -20 | while read -r s; do
    [[ -z "$s" ]] && continue
    local p; p=$("${AWSX[@]}" ec2 describe-snapshot-attribute --snapshot-id "$s" \
                 --attribute createVolumePermission --query 'length(CreateVolumePermissions)' --output text 2>/dev/null)
    [[ "$p" =~ ^[0-9]+$ && "$p" -gt 0 ]] && bad "snapshot $s is SHARED with $p external principal(s) — unshare it"
  done
}

cmd_checklist() {
  banner "Teardown checklist" "for the report; the deliverable asks for the evidence"
  cat <<'TXT'

  Resources
    [ ] terraform destroy completed, zero resources in `terraform state list`
    [ ] verified in the console as well as in the state — they disagree more
        often than they should
    [ ] EVERY region checked, not only the one you deployed to
    [ ] snapshots, AMIs and volumes — these survive instance deletion
    [ ] versioned buckets actually emptied: delete markers are not deletion
    [ ] log groups and exported archives: kept deliberately, or removed deliberately

  Identity and sharing
    [ ] access keys created during the exercise, deleted
    [ ] roles, policies and trust relationships created, removed
    [ ] anything shared with an external account, UNSHARED
        (a shared snapshot is not a cost problem, it is a data problem)

  Proof
    [ ] budget alert LEFT IN PLACE, in case something was missed
    [ ] cost check the following day — the real proof, and the only one
    [ ] lab credentials removed from shell history and config files
        history -c is not enough; check ~/.aws/credentials and ~/.bash_history

  For the report
    [ ] terraform destroy output, saved
    [ ] this checklist, completed, with your name and the date

TXT
  hint "a lab that outlives its purpose is shadow infrastructure"
  hint "and a leaked lab credential is a real credential"
}

case "${1:-all}" in
  terraform) shift; cmd_terraform "$@" ;;
  sweep)     shift; cmd_sweep "$@" ;;
  checklist) shift; cmd_checklist "$@" ;;
  all)       cmd_terraform; say ""; cmd_sweep; say ""; cmd_checklist ;;
  -h|--help) usage 0 ;;
  *) die "unknown: $1" ;;
esac
