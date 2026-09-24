# Approved Patch Repository

This folder holds **pre-approved** patch packages and their Ansible playbooks.
The automation will only add a package to the patch catalog when `metadata.json`
is valid, its `approval_status` is `APPROVED`, and any recorded SHA-256 checksum
matches the local patch file.
