Wazuh Pre-Approved Vulnerability Auto-Patching Pipeline

A defensive security automation project that connects Wazuh vulnerability
detection with a controlled Ansible patch deployment pipeline.

The project is intentionally designed so that a vulnerability is not patched
simply because Wazuh detects it. A patch must already exist in the approved
repository and must match the detected CVE and operating system before the
pipeline can deploy it.

Architecture

Wazuh Agents
    |
    v
Wazuh Indexer / OpenSearch
    |
    |  wazuh_vulnerability_collect.py
    |  Fetch -> Normalize -> Filter
    v
vulnerabilities.csv
    |
    | SCP
    v
Patch Automation Server
    |
    |  patch_pipeline.py
    v
Approved Patch Repository
    |
    | metadata approval + SHA-256 verification
    v
CVE / OS exact matching
    |
    v
Temporary Ansible Inventory
    |
    v
Ansible Playbook Deployment
    |
    v
Windows / Linux Endpoints

Network Topology

The project uses a simple segmented lab design. Vulnerability information is
collected from the Wazuh Indexer, transferred to a dedicated patch automation
server, and remediation is then pushed only to the endpoints that require an
approved patch.

                         Security / Management Network

+-----------------------+        HTTPS : 9200
| Windows/Linux         |-------------------------------+
| Wazuh Agents          |                               |
+-----------------------+                               v
                                              +----------------------+
                                              | Wazuh Indexer /      |
                                              | OpenSearch           |
                                              +----------+-----------+
                                                         |
                                                         | Python collector
                                                         | generates
                                                         | vulnerabilities.csv
                                                         v
                                              +----------------------+
                                              | Wazuh / Collector    |
                                              | Machine              |
                                              +----------+-----------+
                                                         |
                                                         | SCP / SSH : 22
                                                         v
                                              +----------------------+
                                              | Patch Automation     |
                                              | Server               |
                                              | Python + Ansible     |
                                              +----+------------+----+
                                                   |            |
                              HTTP : 8080          |            | SSH : 22
                              patch download       |            | Linux mgmt
                                                   |            |
                                                   |            v
                                                   |      +------------------+
                                                   |      | Linux Endpoints  |
                                                   |      +------------------+
                                                   |
                                                   | WinRM : 5985
                                                   v
                                            +------------------+
                                            | Windows Endpoints|
                                            +------------------+

Data flow

Wazuh agents report endpoint and vulnerability state to the Wazuh platform.

wazuh_vulnerability_collect.py queries the Wazuh Indexer over HTTPS and
creates vulnerabilities.csv.

The CSV is transferred to the patch automation server using SCP.

patch_pipeline.py compares each finding against the pre-approved patch
repository and creates a patch queue for exact CVE/OS matches.

The patch automation server exposes approved patch files to managed hosts
over its patch-server port when deployment begins.

Ansible connects to Windows targets through WinRM and Linux targets through
SSH to execute the required remediation playbook.

What the two scripts do

wazuh_vulnerability_collect.py

Connects to the Wazuh Indexer/OpenSearch API.

Retrieves vulnerability documents from wazuh-states-vulnerabilities-*.

Normalizes Wazuh fields into a simple record containing hostname, OS, CVE,
severity, package and installed version information.

Filters findings by configured severity and package exclusion rules.

Exports the actionable findings to vulnerabilities.csv.

Copies the CSV to the patch automation server over SCP.

patch_pipeline.py

Scans the approved patch repository for metadata.json files.

Rejects packages that are not marked APPROVED.

Re-checks the SHA-256 checksum of approved patch files when a checksum is
present.

Builds a CVE-to-patch catalog.

Matches Wazuh findings to approved patches using the CVE and OS.

Skips findings already reporting the fixed version.

Groups affected hosts by playbook.

Generates a temporary Ansible inventory.

Runs the matching Ansible playbook against only the required endpoints.

Checks the Ansible recap before treating a deployment as successful.

Safety controls built into the design

Pre-approval gate: only repository entries with APPROVED status enter
the patch catalog.

Checksum validation: approved packages can be verified with SHA-256 before
deployment.

Exact CVE matching: no fuzzy or AI-based decision is used to select a
patch.

OS validation: a Windows patch is not matched to an Ubuntu finding, and
vice versa.

Fixed-version check: already-remediated findings can be skipped.

Scoped deployment: hosts are grouped only for the specific playbook they
require.

No secrets in source: credentials are read from environment variables.

Installation

git clone https://github.com/YOUR-USERNAME/wazuh-auto-patching-pipeline.git
cd wazuh-auto-patching-pipeline

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Configuration

Do not put passwords directly in either Python script.

Use .env.example as a reference, then export the required values in your
shell or another secure secret-management method.

Example:

export WAZUH_INDEXER_URL="https://wazuh-indexer.example.local:9200"
export WAZUH_USERNAME="admin"
export WAZUH_PASSWORD="your-secret"
export PATCH_REMOTE_HOST="patch-automation.example.local"

export PATCH_SERVER_BASE_URL="http://patch-automation.example.local:8080"
export WINDOWS_ANSIBLE_USER='DOMAIN\\patch-user'
export WINDOWS_ANSIBLE_PASSWORD="your-secret"

For host mappings:

export HOST_ADDRESS_JSON='{"WindowsAgent":"10.10.10.20","UbuntuAgent":"10.10.10.21"}'

Running the pipeline

1. Collect Wazuh vulnerabilities

On the Wazuh-side machine:

python3 wazuh_vulnerability_collect.py

This creates vulnerabilities.csv and sends it to the configured patch
machine.

2. Run the approved patch pipeline

On the patch automation machine:

python3 patch_pipeline.py

The script builds the approved catalog, creates patch_queue.csv, and runs the
required Ansible playbooks.

Disclaimer

Use this project only in environments where you are authorized to administer
and patch the target systems. Test patches in a lab or staging environment
before production deployment.
