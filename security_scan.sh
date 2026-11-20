#!/usr/bin/env bash

# Enable safer Bash scripting:
# -u: Treat unset variables as errors.
# -o pipefail: Return a failure if any command in a pipeline fails.
# Note: This script does not enable -e because individual checks
# are expected to handle failures without terminating execution.
set -uo pipefail

# Initialize counters to track security check results.
# PASS = Checks that meet the expected security configuration.
# WARN = Checks that require manual review.
# FAIL = Checks that indicate a potentially insecure configuration.
PASS=0
WARN=0
FAIL=0

# Print a PASS message and increment the PASS counter.
pass()    { printf '[PASS] %s\n' "$1"; PASS=$((PASS+1)); }

# Print a WARN message and increment the WARN counter.
warn()    { printf '[WARN] %s\n' "$1"; WARN=$((WARN+1)); }

# Print a FAIL message and increment the FAIL counter.
fail()    { printf '[FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }

# Print a formatted heading to separate security assessment sections.
section() { printf '\n=== %s ===\n' "$1"; }

# Safely read a file if it exists and is readable.
# Return "unknown" when the file cannot be accessed.
# This is useful when checking system files and cgroup configurations.
read_file() {
    if [[ -r "$1" ]]; then cat "$1" 2>/dev/null; else echo unknown; fi
}


# ============================================================
# SECTION 1: IDENTITY AND USER PRIVILEGES
# ============================================================

section "Identity"

# Check whether the script is running as root.
# Running security-sensitive workloads as root increases the
# potential impact of a container or environment compromise.
if [[ "$(id -u)" -eq 0 ]]; then
    fail "Running as root"
else
    pass "Non-root user: $(id -un)"
fi

# Retrieve all groups associated with the current user.
# Membership in certain groups can provide elevated host access.
GROUPS="$(id -nG 2>/dev/null || true)"

# Check for commonly privileged groups:
# docker - May provide control over the Docker daemon.
# lxd    - May provide powerful container management privileges.
# sudo   - May allow administrative command execution.
for group in docker lxd sudo; do
    if [[ " $GROUPS " == *" $group "* ]]; then
        warn "User belongs to privileged group: $group"
    fi
done


# ============================================================
# SECTION 2: LINUX CAPABILITIES
# ============================================================

section "Linux capabilities"

# Read the CapEff field from /proc/self/status.
# CapEff represents the effective Linux capabilities of the process.
CAPS="$(awk '/^CapEff:/ {print $2}' /proc/self/status 2>/dev/null || true)"

# Check whether the process has any effective capabilities.
if [[ "$CAPS" == "0000000000000000" ]]; then
    pass "No effective capabilities"

# If capabilities are present, verify that the value is hexadecimal.
elif [[ "$CAPS" =~ ^[0-9a-fA-F]+$ ]]; then

    # Convert the hexadecimal capability mask into an integer.
    CAP_NUM=$((16#$CAPS))

    # Track whether any specifically dangerous capabilities are found.
    danger=0

    # Check selected high-risk Linux capabilities:
    # CAP_NET_ADMIN   - Network configuration and administration.
    # CAP_SYS_MODULE  - Loading and unloading kernel modules.
    # CAP_SYS_PTRACE  - Tracing and inspecting other processes.
    # CAP_SYS_ADMIN   - Broad administrative operations.
    for entry in "12:CAP_NET_ADMIN" "16:CAP_SYS_MODULE" "19:CAP_SYS_PTRACE" "21:CAP_SYS_ADMIN"; do

        # Extract the capability bit number and capability name.
        bit="${entry%%:*}"
        name="${entry#*:}"

        # Perform a bitwise AND to determine whether the capability is enabled.
        if (( (CAP_NUM & (1 << bit)) != 0 )); then
            fail "Dangerous capability present: $name"
            danger=1
        fi
    done

    # If capabilities exist but none of the selected high-risk
    # capabilities are present, report them for further review.
    (( danger == 0 )) && warn "Non-dangerous capabilities present: $CAPS"

else
    # Report a warning if capability information cannot be interpreted.
    warn "Cannot inspect capabilities"
fi


# ============================================================
# SECTION 3: PRIVILEGE ESCALATION PROTECTION
# ============================================================

section "Privilege escalation"

# Read the NoNewPrivs value from /proc/self/status.
# NoNewPrivs prevents processes from gaining additional privileges
# through operations such as executing setuid or setgid programs.
NNP="$(awk '/^NoNewPrivs:/ {print $2}' /proc/self/status 2>/dev/null || true)"

# Value 1 means the no-new-privileges security setting is enabled.
if [[ "$NNP" == "1" ]]; then
    pass "no-new-privileges enabled"
else
    # A value of 0 or unavailable information is treated as a failure.
    fail "no-new-privileges not enabled"
fi


# ============================================================
# SECTION 4: SECCOMP SECURITY
# ============================================================

section "Seccomp"

# Read the Seccomp status from /proc/self/status.
# Seccomp restricts the system calls that a process can execute.
SECCOMP="$(awk '/^Seccomp:/ {print $2}' /proc/self/status 2>/dev/null || true)"

# Interpret the Seccomp mode:
# 0 = Seccomp disabled.
# 1 = Strict mode.
# 2 = Seccomp filter mode.
case "$SECCOMP" in
    2) pass "Seccomp filter active" ;;
    1) warn "Seccomp strict mode" ;;
    0) fail "Seccomp disabled" ;;
    *) warn "Seccomp status unavailable" ;;
esac


# ============================================================
# SECTION 5: RESOURCE LIMITS
# ============================================================

section "Resource limits"

# Read cgroup v2 resource limits.
# These files provide information about the resource restrictions
# applied to the current container or process group.
MEM="$(read_file /sys/fs/cgroup/memory.max)"
CPU="$(read_file /sys/fs/cgroup/cpu.max)"
PIDS="$(read_file /sys/fs/cgroup/pids.max)"

# If the cgroup v2 memory file is unavailable,
# attempt to read the equivalent cgroup v1 memory limit.
if [[ "$MEM" == "unknown" ]]; then
    MEM="$(read_file /sys/fs/cgroup/memory/memory.limit_in_bytes)"
fi

# If the cgroup v2 CPU configuration is unavailable,
# attempt to retrieve the cgroup v1 CPU quota and period.
if [[ "$CPU" == "unknown" ]]; then
    QUOTA="$(read_file /sys/fs/cgroup/cpu/cpu.cfs_quota_us)"
    PERIOD="$(read_file /sys/fs/cgroup/cpu/cpu.cfs_period_us)"

    # A quota of -1 means no CPU quota is configured.
    # Otherwise, store the quota and period for reporting.
    if [[ "$QUOTA" != "unknown" && "$PERIOD" != "unknown" && "$QUOTA" != "-1" ]]; then
        CPU="${QUOTA}/${PERIOD}"
    else
        CPU="unknown"
    fi
fi

# If the cgroup v2 PID limit file is unavailable,
# attempt to retrieve the equivalent cgroup v1 setting.
if [[ "$PIDS" == "unknown" ]]; then
    PIDS="$(read_file /sys/fs/cgroup/pids/pids.max)"
fi

# Report the memory limit if a finite value is available.
# "max" indicates that no explicit cgroup v2 limit is configured.
if [[ "$MEM" != "unknown" && "$MEM" != "max" ]]; then
    pass "Memory limit: $MEM"
else
    warn "Memory limit not confirmed"
fi

# Report the CPU quota if a finite configuration is available.
if [[ "$CPU" != "unknown" && "$CPU" != "max" ]]; then
    pass "CPU limit: $CPU"
else
    warn "CPU limit not confirmed"
fi

# Report the maximum number of processes allowed.
if [[ "$PIDS" != "unknown" && "$PIDS" != "max" ]]; then
    pass "Process limit: $PIDS"
else
    warn "Process limit not confirmed"
fi


# ============================================================
# SECTION 6: DANGEROUS INTERFACES AND DEVICES
# ============================================================

section "Dangerous interfaces"

# Check whether the Docker daemon socket is exposed.
# Access to this socket can potentially provide control over
# Docker containers and the underlying host.
if [[ -S /var/run/docker.sock || -S /run/docker.sock ]]; then
    fail "Docker socket exposed"
else
    pass "No standard Docker socket"
fi

# Check whether the KVM device is accessible.
# KVM provides hardware-assisted virtualization capabilities.
if [[ -e /dev/kvm ]]; then
    warn "KVM device exposed"
else
    pass "No KVM device"
fi

# Check for direct kernel memory device exposure.
# These interfaces can provide highly sensitive system access.
if [[ -e /dev/mem || -e /dev/kmem ]]; then
    fail "Kernel memory device exposed"
else
    pass "No kernel memory devices"
fi


# ============================================================
# SECTION 7: HOST FILESYSTEM EXPOSURE
# ============================================================

section "Host filesystem exposure"

# Check for common host filesystem mount locations.
# Their presence may indicate that host directories are mounted
# inside the current environment.
for path in /mnt/c/Windows /mnt/c/Users /host /run/host-services; do
    if [[ -e "$path" ]]; then
        fail "Potential host filesystem exposure: $path"
    fi
done

# Check whether the current process can read mount information.
# /proc/self/mountinfo provides details about mounted filesystems.
if [[ -r /proc/self/mountinfo ]]; then
    pass "Mount information readable"

    # Look for a Docker socket mount in the current mount namespace.
    if grep -Fq '/var/run/docker.sock' /proc/self/mountinfo; then
        fail "Docker socket mount detected"
    fi
else
    warn "Mount information unavailable"
fi

# ============================================================
# SECTION: CREDENTIAL AND SECRET EXPOSURE
# ============================================================

section "Credential exposure"

# Check for commonly used secrets and credentials exposed through
# environment variables.
#
# Categories covered:
# - Source control and code hosting
# - Cloud providers
# - Container registries
# - CI/CD platforms
# - Infrastructure as Code
# - Databases
# - Messaging and notification services
# - Package registries
# - Authentication and signing
# - Monitoring and observability
#
# Only variable names are reported.
# Secret values are NEVER printed.

SECRET_VARIABLES=(
    # --------------------------------------------------------
    # GitHub / GitLab / Bitbucket
    # --------------------------------------------------------
    GITHUB_TOKEN
    GH_TOKEN
    GH_ENTERPRISE_TOKEN
    GITHUB_ENTERPRISE_TOKEN
    GITLAB_TOKEN
    GITLAB_PRIVATE_TOKEN
    CI_JOB_TOKEN
    BITBUCKET_TOKEN
    BITBUCKET_USERNAME
    BITBUCKET_APP_PASSWORD

    # --------------------------------------------------------
    # AWS
    # --------------------------------------------------------
    AWS_ACCESS_KEY_ID
    AWS_SECRET_ACCESS_KEY
    AWS_SESSION_TOKEN
    AWS_SECURITY_TOKEN
    AWS_WEB_IDENTITY_TOKEN_FILE
    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
    AWS_CONTAINER_CREDENTIALS_FULL_URI

    # --------------------------------------------------------
    # Microsoft Azure
    # --------------------------------------------------------
    AZURE_CLIENT_ID
    AZURE_CLIENT_SECRET
    AZURE_TENANT_ID
    AZURE_ACCESS_TOKEN
    ARM_CLIENT_ID
    ARM_CLIENT_SECRET
    ARM_ACCESS_KEY
    ARM_SAS_TOKEN

    # --------------------------------------------------------
    # Google Cloud Platform
    # --------------------------------------------------------
    GOOGLE_APPLICATION_CREDENTIALS
    GOOGLE_CREDENTIALS
    GOOGLE_CLOUD_KEYFILE_JSON
    GCLOUD_SERVICE_KEY
    GCP_ACCESS_TOKEN
    GOOGLE_OAUTH_ACCESS_TOKEN

    # --------------------------------------------------------
    # Kubernetes
    # --------------------------------------------------------
    KUBECONFIG
    K8S_TOKEN
    KUBE_TOKEN
    KUBE_PASSWORD
    KUBERNETES_SERVICE_ACCOUNT_TOKEN

    # --------------------------------------------------------
    # HashiCorp Vault / Terraform
    # --------------------------------------------------------
    VAULT_TOKEN
    VAULT_CLIENT_TOKEN
    VAULT_PASSWORD
    TF_VAR_password
    TF_VAR_token
    TF_VAR_client_secret
    TF_VAR_access_key
    TF_VAR_secret_key
    TF_CLI_CONFIG_FILE

    # --------------------------------------------------------
    # Docker / Container Registries
    # --------------------------------------------------------
    DOCKER_AUTH_CONFIG
    DOCKER_PASSWORD
    DOCKER_USERNAME
    DOCKER_TOKEN
    REGISTRY_PASSWORD
    REGISTRY_AUTH
    QUAY_PASSWORD
    HARBOR_PASSWORD

    # --------------------------------------------------------
    # CI/CD platforms
    # --------------------------------------------------------
    JENKINS_API_TOKEN
    JENKINS_TOKEN
    CIRCLECI_TOKEN
    TRAVIS_TOKEN
    BUILDKITE_API_TOKEN
    DRONE_TOKEN
    TEAMCITY_PASSWORD
    GITLAB_RUNNER_TOKEN
    AZURE_DEVOPS_EXT_PAT
    SYSTEM_ACCESSTOKEN

    # --------------------------------------------------------
    # Database credentials
    # --------------------------------------------------------
    DATABASE_URL
    DATABASE_PASSWORD
    DB_PASSWORD
    DB_USER
    DB_USERNAME
    MYSQL_PASSWORD
    MYSQL_ROOT_PASSWORD
    POSTGRES_PASSWORD
    POSTGRES_USER
    PG_PASSWORD
    PGPASSWORD
    MONGO_URI
    MONGODB_URI
    REDIS_PASSWORD
    REDIS_URL
    SQLSERVER_PASSWORD

    # --------------------------------------------------------
    # SSH / TLS / Certificates
    # --------------------------------------------------------
    SSH_AUTH_SOCK
    SSH_PRIVATE_KEY
    SSH_KEY
    PRIVATE_KEY
    TLS_PRIVATE_KEY
    TLS_CERTIFICATE
    SSL_CERT_FILE
    SSL_KEY_FILE
    CERT_PASSWORD
    KEY_PASSWORD

    # --------------------------------------------------------
    # Package registries
    # --------------------------------------------------------
    NPM_TOKEN
    NODE_AUTH_TOKEN
    PYPI_TOKEN
    TWINE_PASSWORD
    POETRY_HTTP_BASIC_PASSWORD
    ARTIFACTORY_TOKEN
    ARTIFACTORY_PASSWORD
    NEXUS_PASSWORD
    GEM_HOST_API_KEY

    # --------------------------------------------------------
    # Messaging / Communication services
    # --------------------------------------------------------
    SLACK_TOKEN
    SLACK_BOT_TOKEN
    SLACK_WEBHOOK_URL
    DISCORD_TOKEN
    DISCORD_WEBHOOK
    TELEGRAM_BOT_TOKEN
    TWILIO_AUTH_TOKEN
    SENDGRID_API_KEY
    MAILGUN_API_KEY
    SMTP_PASSWORD

    # --------------------------------------------------------
    # Monitoring / Observability
    # --------------------------------------------------------
    DATADOG_API_KEY
    DATADOG_APP_KEY
    NEW_RELIC_LICENSE_KEY
    NEW_RELIC_API_KEY
    SENTRY_AUTH_TOKEN
    SENTRY_DSN
    HONEYCOMB_API_KEY
    GRAFANA_API_KEY
    PROMETHEUS_PASSWORD

    # --------------------------------------------------------
    # Authentication / OAuth / Application secrets
    # --------------------------------------------------------
    API_KEY
    API_SECRET
    API_TOKEN
    ACCESS_TOKEN
    REFRESH_TOKEN
    AUTH_TOKEN
    AUTH_SECRET
    CLIENT_SECRET
    CLIENT_PASSWORD
    OAUTH_CLIENT_SECRET
    OAUTH_ACCESS_TOKEN
    OAUTH_REFRESH_TOKEN
    JWT_SECRET
    SESSION_SECRET
    SECRET_KEY
    ENCRYPTION_KEY
    SIGNING_KEY
    WEBHOOK_SECRET

    # --------------------------------------------------------
    # Common application frameworks
    # --------------------------------------------------------
    DJANGO_SECRET_KEY
    FLASK_SECRET_KEY
    RAILS_MASTER_KEY
    NEXTAUTH_SECRET
    AUTH_SECRET
    NUXT_SESSION_PASSWORD
    LARAVEL_APP_KEY
    APP_KEY
)

# Track detected credentials.
SECRET_COUNT=0

# Iterate through all known sensitive environment variable names.
for variable in "${SECRET_VARIABLES[@]}"; do

    # Indirect expansion retrieves the variable value without
    # exposing it in terminal output.
    if [[ -n "${!variable:-}" ]]; then

        # Report only the variable name, never its contents.
        fail "Potential secret exposed through environment variable: $variable"

        # Increment the number of detected populated variables.
        SECRET_COUNT=$((SECRET_COUNT + 1))
    fi
done

# Display a summary of the environment variable scan.
if (( SECRET_COUNT == 0 )); then
    pass "No populated known secret environment variables detected"
else
    warn "Detected $SECRET_COUNT populated potential secret variables"
fi



# Check whether an SSH agent socket is available.
# An accessible agent may allow authentication using loaded SSH keys.
if [[ -n "${SSH_AUTH_SOCK:-}" ]]; then
    warn "SSH agent socket is available"
else
    pass "No SSH agent socket"
fi

# Check for the Git credentials file.
# This file may contain credentials used for Git authentication.
if [[ -f "$HOME/.git-credentials" ]]; then
    fail "Git credential file exists"
else
    pass "No Git credential file"
fi

# Check whether GitHub CLI authentication configuration exists.
# This file may contain authentication-related information.
if [[ -f "$HOME/.config/gh/hosts.yml" ]]; then
    warn "GitHub CLI authentication file exists"
else
    pass "No GitHub CLI authentication file"
fi


# ============================================================
# SECTION 9: FINAL SECURITY REPORT
# ============================================================

section "Final report"

# Display the total number of checks in each category.
printf '\nPASS: %s\n' "$PASS"
printf 'WARN: %s\n' "$WARN"
printf 'FAIL: %s\n' "$FAIL"

# Determine the overall security assessment.
#
# FAIL > 0:
# At least one security check failed.
# Exit code 1 indicates that security issues were detected.
#
# WARN > 0:
# No failures were detected, but some configurations require review.
# Exit code 0 indicates that the script completed successfully.
#
# No failures or warnings:
# All implemented checks passed.
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
