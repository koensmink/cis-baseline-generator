# Environment Scan

`cis-environment-scan` creates a read-only inventory of an Intune or Group Policy
environment. Python runs on one central management system or automation runner;
it is not installed on managed workstations or servers.

The resulting `current-state.json` is the observed-environment input for future
CIS gap analysis. The scanner does not parse CIS PDFs, change policies, alter
assignments, contact individual devices, or deploy remediation.

## How it works

```text
Central runner
    |
    +-- Microsoft Graph ------> Intune policies and managed-device inventory
    |
    +-- exported GPO XML -----> On-premises Group Policy configuration
                    |
                    v
             current-state.json
```

The central runner can be an administrator workstation, a management VM, a
container, a self-hosted CI runner, or a hosted runner with approved network
access and workload identity. Managed endpoints do not need Python, an inbound
port, or a local copy of this repository.

## Installation on the runner

```bash
git clone https://github.com/koensmink/cis-baseline-generator.git
cd cis-baseline-generator
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
cis-environment-scan --help
```

On Windows PowerShell, activate the virtual environment with:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Intune live scan

### Required access

Use a Microsoft Entra application, managed identity, or delegated administrator
session with Microsoft Graph read permissions appropriate to the selected data.
The intended application permissions are:

- `DeviceManagementConfiguration.Read.All`; and
- `DeviceManagementManagedDevices.Read.All`.

Tenant administrator consent and a valid Intune licence are required by Microsoft.
Do not grant write, wipe, reset, device-action, or privileged-operation permissions
to the scanner identity.

### Run the scan

Acquire a short-lived Graph access token through the organisation's approved
authentication process and place it in a local environment variable:

```bash
export MS_GRAPH_ACCESS_TOKEN="<short-lived-access-token>"

cis-environment-scan \
  --source intune \
  --tenant-id "<tenant-id>" \
  -o current-state.json
```

The token is sent only as the Graph bearer token. It is not written to the
snapshot, console summary, or provenance fields.

To use another environment-variable name:

```bash
cis-environment-scan \
  --source intune \
  --access-token-env CUSTOMER_GRAPH_TOKEN \
  -o current-state.json
```

### Information collected

The live Intune adapter requests:

- Settings Catalog configuration policies and their settings;
- legacy device configuration profiles;
- imported Group Policy configurations and definition values;
- include and exclude assignments;
- assignment filters;
- managed-device operating system and version;
- Intune compliance state;
- encryption inventory;
- management agent; and
- last synchronization time.

It derives observation signals for disk encryption, endpoint protection, firewall,
NTLM, and SMBv1 from the collected configuration.

### Partial collection

Microsoft Graph permissions and API availability can differ by tenant. When one
collection cannot be read, the scanner still writes the available evidence but:

- sets snapshot status to `partial`;
- records each failure in `collection_errors`; and
- returns exit status `2`.

This prevents automation from treating an incomplete scan as complete. Missing
data becomes `not_observed`, never `non_compliant`.

## Offline Intune scan

Restricted environments can export Graph responses separately and scan them
without a live tenant connection:

```bash
cis-environment-scan \
  --source intune \
  --input intune-export.json \
  -o current-state.json
```

The input JSON object can contain these collections:

```json
{
  "configurationPolicies": [],
  "deviceConfigurations": [],
  "groupPolicyConfigurations": [],
  "managedDevices": []
}
```

Each collection can be a direct array or a Microsoft Graph object containing a
`value` array. Expanded `settings` and `assignments` are accepted. The scanner
records a SHA-256 hash of the supplied export.

## Group Policy scan

Run the Microsoft GroupPolicy module on a domain-management workstation or
management server:

```powershell
Get-GPOReport -All -ReportType Xml -Path C:\SecureExport\all-gpos.xml
```

This PowerShell command is the only component that needs access to Active
Directory Group Policy. Python is not required on domain controllers or managed
servers. Transfer the XML through the organisation's approved secure process and
scan it on the central runner:

```bash
cis-environment-scan \
  --source gpo \
  --input all-gpos.xml \
  -o current-state-gpo.json
```

The input can be one individual GPO XML report, one combined
`Get-GPOReport -All` report, or a directory containing multiple XML reports. GPO
links are recorded as assignments. An XML report describes configured policy,
not the effective Resultant Set of Policy on a particular computer.

## Remote and scheduled execution

### Recommended production pattern

```text
Manual or scheduled workflow
          |
          v
OIDC or managed-identity sign-in
          |
          v
Short-lived read-only Graph token
          |
          v
cis-environment-scan
          |
          +--> encrypted customer storage
          +--> later cis-baseline-assess
```

| Pattern | Appropriate use |
|---|---|
| Customer-hosted management VM | Simple manual scans and restricted tenants |
| Self-hosted CI runner | Access must remain inside the customer network |
| Hosted CI with OIDC | Repeatable scans without a stored client secret |
| Managed cloud job | Scheduled scanning using a managed identity |

With GitHub Actions, use OpenID Connect and a federated identity credential where
possible. Restrict the workflow with environment approval and read-only Graph
application permissions. The scanner accepts the resulting Graph token through
an environment variable; token acquisition remains a separate workflow step.

## Sensitive output

`current-state.json`, Intune exports, and GPO reports can contain device and policy
names, tenant and group identifiers, assignments, exclusions, operating-system
versions, configuration values, and security architecture details.

Do not commit these files, attach them to a public workflow run, or publish them as
artifacts from this public repository. Store them in customer-approved encrypted
storage with limited retention and access logging.

The repository ignores common local names such as `current-state*.json`,
`intune-export*.json`, and `gpo-reports/`. Custom names still require operator
care.

## Snapshot contents

The versioned `CurrentStateSnapshot` contains:

- collection status and observation scopes;
- source type, timestamp, collector version, input hash, and source reference;
- normalized policies and declared settings;
- include/exclude assignments and filters where available;
- managed-device inventory where available;
- potential conflicts and security capability observations;
- warnings and collection errors; and
- deterministic policy, setting, asset, and conflict counts.

Potential conflicts mean that the same normalized setting identity has different
declared values. This is not proof of an effective conflict because assignments
may not overlap.

## Trust boundary

The scanner deliberately distinguishes:

1. **Declared configuration** — what an Intune policy or GPO specifies.
2. **Device inventory** — properties that the management source reports.
3. **Effective state** — what a particular device actually applied.

The current collectors provide the first two scopes. They do not claim complete
effective-state verification. Future `cis-baseline-assess` and validation adapters
can combine this snapshot with per-setting status, Resultant Set of Policy, and
device evidence.

## Exit status and troubleshooting

| Status | Meaning |
|---|---|
| `0` | Scan completed without collection errors |
| `2` | Invalid command/input or a partial live collection |

Common causes of a partial Intune scan are missing Graph permissions, absent
administrator consent, missing Intune licensing, or an API unavailable for the
tenant. Inspect `status`, `warnings`, and `collection_errors` before using the
snapshot downstream.

## Downstream contract

`current-state.json` is designed as the observed-state input for a future command:

```bash
cis-baseline-assess \
  controls.jsonl \
  --current-state current-state.json \
  -o assessment
```

That layer will compare benchmark recommendations with observed configuration
while retaining source provenance, uncertainty, conflicts, and collection gaps.
