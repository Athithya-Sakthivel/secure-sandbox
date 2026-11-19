
#!/usr/bin/env bash
#
# Minimal Linux Dev Container security audit
# Read-only. No external dependencies.
#

set -uo pipefail

PASS=0
WARN=0
FAIL=0

pass() {
    printf '[PASS] %s\n' "$1"
    ((PASS+=1))
}

warn() {
    printf '[WARN] %s\n' "$1"
    ((WARN+=1))
}

fail() {
    printf '[FAIL] %s\n' "$1"
    ((FAIL+=1))
}

section() {
    printf '\n=== %s ===\n' "$1"
}

read_file() {
    [[ -r "$1" ]] && cat "$1" 2>/dev/null || echo unknown
}

section "Identity"

if [[ "$(id -u)" -eq 0 ]]; then
    fail "Running as root"
else
    pass "Non-root user: $(id -un)"
fi

GROUPS="$(id -nG 2>/dev/null || true)"

for group in docker lxd sudo; do
    if [[ " $GROUPS " == *" $group "* ]]; then
        warn "User belongs to privileged group: $group"
    fi
done

section "Linux capabilities"

CAPS="$(awk '/^CapEff:/ {print $2}' /proc/self/status 2>/dev/null || true)"

if [[ "$CAPS" == "0000000000000000" ]]; then
    pass "No effective capabilities"
elif [[ "$CAPS" =~ ^[0-9a-fA-F]+$ ]]; then
    warn "Effective capabilities present: $CAPS"

    CAP_NUM=$((16#$CAPS))

    for entry in \
        "12:CAP_NET_ADMIN" \
        "16:CAP_SYS_MODULE" \
        "19:CAP_SYS_PTRACE" \
        "21:CAP_SYS_ADMIN"
    do
        bit="${entry%%:*}"
        name="${entry#*:}"

        if (( (CAP_NUM & (1 << bit)) != 0 )); then
            fail "Dangerous capability present: $name"
        fi
    done
else
    warn "Cannot inspect capabilities"
fi

section "Privilege escalation"

NNP="$(awk '/^NoNewPrivs:/ {print $2}' /proc/self/status 2>/dev/null || true)"

if [[ "$NNP" == "1" ]]; then
    pass "no-new-privileges enabled"
else
    fail "no-new-privileges not enabled"
fi

section "Seccomp"

SECCOMP="$(awk '/^Seccomp:/ {print $2}' /proc/self/status 2>/dev/null || true)"

case "$SECCOMP" in
    2) pass "Seccomp filter active" ;;
    1) warn "Seccomp strict mode" ;;
    0) fail "Seccomp disabled" ;;
    *) warn "Seccomp status unavailable" ;;
esac

section "Resource limits"

MEM="$(read_file /sys/fs/cgroup/memory.max)"
CPU="$(read_file /sys/fs/cgroup/cpu.max)"
PIDS="$(read_file /sys/fs/cgroup/pids.max)"

# Support cgroup v1 as well.
if [[ "$MEM" == "unknown" ]]; then
    MEM="$(read_file /sys/fs/cgroup/memory/memory.limit_in_bytes)"
fi

if [[ "$CPU" == "unknown" ]]; then
    QUOTA="$(read_file /sys/fs/cgroup/cpu/cpu.cfs_quota_us)"
    PERIOD="$(read_file /sys/fs/cgroup/cpu/cpu.cfs_period_us)"
    CPU="$QUOTA/$PERIOD"
fi

if [[ "$PIDS" == "unknown" ]]; then
    PIDS="$(read_file /sys/fs/cgroup/pids/pids.max)"
fi

if [[ "$MEM" != "unknown" && "$MEM" != "max" ]]; then
    pass "Memory limit: $MEM"
else
    warn "Memory limit not confirmed"
fi

if [[ "$CPU" != "unknown" && "$CPU" != "max" && "$CPU" != "-1/"* ]]; then
    pass "CPU limit: $CPU"
else
    warn "CPU limit not confirmed"
fi

if [[ "$PIDS" != "unknown" && "$PIDS" != "max" ]]; then
    pass "Process limit: $PIDS"
else
    warn "Process limit not confirmed"
fi

section "Dangerous interfaces"

if [[ -S /var/run/docker.sock || -S /run/docker.sock ]]; then
    fail "Docker socket exposed"
else
    pass "No standard Docker socket"
fi

if [[ -e /dev/kvm ]]; then
    warn "KVM device exposed"
else
    pass "No KVM device"
fi

if [[ -e /dev/mem || -e /dev/kmem ]]; then
    fail "Kernel memory device exposed"
else
    pass "No kernel memory devices"
fi

section "Host filesystem exposure"

for path in \
    /mnt/c/Windows \
    /mnt/c/Users \
    /host \
    /run/host-services
do
    if [[ -e "$path" ]]; then
        fail "Potential host filesystem exposure: $path"
    fi
done

if [[ -r /proc/self/mountinfo ]]; then
    pass "Mount information readable"

    if grep -Fq '/var/run/docker.sock' /proc/self/mountinfo; then
        fail "Docker socket mount detected"
    fi
else
    warn "Mount information unavailable"
fi

section "Credential exposure"

for variable in \
    GITHUB_TOKEN \
    GH_TOKEN \
    GH_ENTERPRISE_TOKEN \
    GITHUB_ENTERPRISE_TOKEN \
    AWS_ACCESS_KEY_ID \
    AWS_SECRET_ACCESS_KEY \
    AZURE_CLIENT_SECRET
do
    if [[ -n "${!variable:-}" ]]; then
        fail "$variable is present"
    else
        pass "$variable is empty or absent"
    fi
done

if [[ -n "${SSH_AUTH_SOCK:-}" ]]; then
    warn "SSH agent socket is available"
else
    pass "No SSH agent socket"
fi

if [[ -f "$HOME/.git-credentials" ]]; then
    fail "Git credential file exists"
else
    pass "No Git credential file"
fi

if [[ -f "$HOME/.config/gh/hosts.yml" ]]; then
    warn "GitHub CLI authentication file exists"
else
    pass "No GitHub CLI authentication file"
fi

section "Final report"

printf '\n'
printf 'PASS: %s\n' "$PASS"
printf 'WARN: %s\n' "$WARN"
printf 'FAIL: %s\n' "$FAIL"

if (( FAIL > 0 )); then
    printf '\nRESULT: SECURITY CHECKS FAILED\n'
    exit 1
elif (( WARN > 0 )); then
    printf '\nRESULT: REVIEW WARNINGS\n'
    exit 0
else
    printf '\nRESULT: ALL IMPLEMENTED CHECKS PASSED\n'
    exit 0
fi
