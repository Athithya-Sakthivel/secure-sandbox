# Secure Sandbox

A hardened, isolated development environment designed for technical take-home assignments. Inspired by recent high-profile supply chain attacks (such as the 2026 Binance DevOps compromise), this sandbox minimizes the attack surface by enforcing strict container security policies, resource limits, and privilege restrictions.

> **⚠️ IMPORTANT: Do Not Use GitHub Codespaces**  
> GitHub Codespaces automatically injects platform-level secrets (e.g., `GITHUB_TOKEN`) and often ignores restrictive Docker `runArgs` (such as `--security-opt=no-new-privileges`). For maximum security and accurate validation, this sandbox **must be run locally** using Docker Desktop.

## Why Use This?

* **Consistency:** Every candidate receives the exact same, pre-configured environment, eliminating "it works on my machine" issues.
* **Security:** The container runs as a non-root user, restricts system privileges, limits resource usage (CPU, memory, processes), and blocks access to the host machine.
* **Validation:** An automated security scan verifies the environment is properly isolated and free of exposed credentials before the assignment begins.

## Prerequisites

* **Docker:** Installed and running without `sudo` access. *(If not already configured, run: `sudo usermod -aG docker $USER && newgrp docker`)*
* **Visual Studio Code:** Installed with the [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers).

## Setup Instructions

**1. Clone the repository:**
```bash
git clone https://github.com/Athithya-Sakthivel/secure-sandbox.git
cd secure-sandbox
```

**2. Open in VS Code:**
```bash
code .
```

**3. Rebuild the Dev Container:**
* Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on macOS).
* Type and select: **Dev Containers: Rebuild Container Without Cache**.
* Wait for the container to build and initialize.

**4. Verify the Environment:**
Once the integrated terminal is ready inside the container, run the security scan:
```bash
bash security_scan.sh
```

## Expected Results

A properly configured local environment will show `[PASS]` messages. Key indicators of a secure setup include:
* `[PASS] Non-root user: vscode`
* `[PASS] no-new-privileges enabled`
* `[PASS] No populated known secret environment variables detected`

If the script returns any `[FAIL]` messages, the environment is not correctly isolated, or secrets are present and should not be used for the assignment.

---

<img width="1920" height="1014" alt="image" src="https://github.com/user-attachments/assets/638f1c44-dafa-4beb-b582-d4aaa3fb7910" />

----

## Configuration Details

* **Base Image:** `mcr.microsoft.com/devcontainers/base:ubuntu-24.04@sha256:d94c97dd9cacf183d0a6fd12a8e87b526e9e928307674ae9c94139139c0c6eae`
* **User:** Non-root `vscode` user
* **Resource Limits:** 4GB Memory, 2 CPUs, 512 PIDs
* **Security Options:** `--security-opt=no-new-privileges` enforced via Docker run arguments
