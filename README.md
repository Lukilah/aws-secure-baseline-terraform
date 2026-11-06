# Automated AWS Secure Baseline with Terraform, Checkov & GitHub Actions

![CI Security Scan](https://github.com/Lukilah/aws-secure-baseline-terraform/actions/workflows/security-scan.yml/badge.svg)
[![IaC: Terraform](https://img.shields.io/badge/IaC-Terraform_>=1.5-blue.svg)](https://www.terraform.io/)
[![Security: Checkov](https://img.shields.io/badge/Secured_by-Checkov-green.svg)](https://www.checkov.io/)

A DevSecOps repository implementing a hardened AWS baseline architecture (VPC, private/public subnets, S3, IAM, and Security Groups) provisioned via Terraform and audited against CIS/Prisma Cloud benchmarks using Checkov in a continuous integration (CI) pipeline.

---

## 1. Overview & Architecture Rationale

Deploying cloud infrastructure manually via the management console introduces configuration drift and security blind spots. This project demonstrates a **shift-left security model**: writing cloud infrastructure as code (IaC), intentionally introducing enterprise anti-patterns, automatically catching violations via static analysis, and enforcing remediation policies before resources are ever provisioned in AWS.

### Architecture Components
* **Virtual Private Cloud (VPC)**: Multi-subnet CIDR allocation (`10.0.0.0/16`) in `eu-central-1` (Frankfurt) with explicit DNS support and hostnames enabled.
* **Network Segregation**: Disables automatic public IPv4 allocations on subnets; locks down the VPC default security group to drop all inbound and outbound traffic.
* **Network Observability**: Centralized VPC Flow Logs streaming directly to secure S3 storage for audit and forensics.
* **Storage Hardening (S3)**: Enforces S3 Public Access Block (all 4 flags), customer-managed KMS encryption, versioning for state protection, and lifecycle expiration policies.
* **Identity & Access Management (IAM)**: Scoped policies strictly enforcing the Principle of Least Privilege (PoLP), replacing dangerous wildcard permissions with explicit ARNs.

---

## 2. Before vs. After Security Metrics

Using Checkov static analysis across the baseline infrastructure, the configuration was systematically hardened from a high-risk baseline to full pipeline compliance:

| Metric | Deliberately Insecure Baseline | Hardened Production Baseline |
| :--- | :---: | :---: |
| **Checkov Status** | ❌ FAILED |  PASSED |
| **Passed Checks** | 10 | 28 |
| **Failed Checks** | **21** | **0** |
| **Documented Exceptions** | 0 | 4 |
| **CI/CD Pipeline State** | Broken (Red) | Passing (Green) |

### Pipeline Proof
* **Insecure Run (Red)**: Flagged open management ports, unencrypted storage, and excessive IAM privilege escalations.
* **Remediated Run (Green)**: All 21 check failures resolved or accounted for with security justifications.

---

## 3. Key Remediations Implemented

1. **Eliminated Public Ingress (Port 22) & Subnet Exposure (`CKV_AWS_24`, `CKV_AWS_130`)**:
   * Removed ingress `0.0.0.0/0:22` to mitigate public brute-force and credential-stuffing attacks. Recommended administration via AWS Systems Manager (SSM) Session Manager.
   * Disabled `map_public_ip_on_launch` across subnets to prevent unexpected instance exposure.
2. **VPC Default Security Group Hardening (`CKV2_AWS_12`)**:
   * Adopted `aws_default_security_group` in Terraform with zero inbound or outbound rules, neutralizing the default AWS behavior of unrestricted intra-VPC communication.
3. **S3 Public Access Block & Bucket Versioning (`CKV2_AWS_6`, `CKV_AWS_21`)**:
   * Configured `aws_s3_bucket_public_access_block` with all four flags (`block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets`) set to `true`.
   * Enabled S3 Versioning to defend against malicious object overwriting and accidental deletion.
4. **Enforced Encryption at Rest & Lifecycle Controls (`CKV_AWS_145`, `CKV_AWS_300`, `CKV2_AWS_61`)**:
   * Configured default server-side encryption via AWS Key Management Service (`aws:kms`).
   * Configured lifecycle rules to abort incomplete multipart uploads after 7 days to eliminate orphaned storage costs and lingering data fragments.
5. **IAM Principle of Least Privilege (`CKV_AWS_62`, `CKV_AWS_63`, `CKV_AWS_355`)**:
   * Refactored wildcard statements (`Action: "*"` on `Resource: "*"`) into strict read/write primitives (`s3:ListBucket`, `s3:GetObject`, `s3:PutObject`) scoped strictly to the bucket's ARN.

---

## 4. Documented Exceptions (Risk vs. Operational Rationale)

In real cloud engineering environments, blind adherence to scan rules without architectural context incurs prohibitive billing and operational overhead. The following checks were intentionally skipped with rationale in code:

* **`CKV_AWS_144` (Cross-Region S3 Replication)**: Skipped (`#checkov:skip=CKV_AWS_144`). Multi-region replication introduces inter-region data transfer fees and dual storage overhead inappropriate for single-region baseline demonstration assets.
* **`CKV_AWS_18` (S3 Bucket Access Logging)**: Skipped (`#checkov:skip=CKV_AWS_18`). Avoids a recursive logging loop where access logs for the logging bucket trigger additional log events without an auxiliary logging target.
* **`CKV2_AWS_62` (S3 Event Notifications)**: Skipped (`#checkov:skip=CKV2_AWS_62`). No downstream consumers (SNS/SQS/Lambda) are attached to this data layer.
* **`CKV2_AWS_5` (Security Group Resource Binding)**: Skipped (`#checkov:skip=CKV2_AWS_5`). This module defines foundational baseline networking ahead of compute layer deployment.

---

## 5. Local Reproduction & Verification

To run this scan locally:

```bash
# 1. Clone repository
git clone [https://github.com/Lukilah/aws-secure-baseline-terraform.git](https://github.com/Lukilah/aws-secure-baseline-terraform.git)
cd aws-secure-baseline-terraform

# 2. Initialize Terraform without remote state
terraform init -backend=false
terraform validate

# 3. Execute Checkov static analysis
checkov -d . --framework terraform --compact
```
---

### 6. Takeaways
* **a) Defaults in Cloud Providers are Rarely "Secure by Default"**: AWS prioritizes convenience and backward compatibility (e.g., default security groups allowing all internal communication, subnets auto-assigning public IPs). Production readiness requires active hardening as code.
* **b) Storage Hygiene Directly Impacts Cost & Security**: Failing to abort incomplete multipart uploads (CKV_AWS_300) leaves hidden binary parts accumulating storage costs without visible bucket objects.
* **c) DevSecOps Balances Enforcement with Context**: Static analysis tools are opinionated. Demonstrating the ability to weigh risk versus operational overhead through documented, defensible skips is essential for cloud engineering pragmatism.


## 7. Threat Model & Security Architecture Review

A comprehensive architectural threat model and compliance review was performed for this baseline:

* **Frameworks Applied**: STRIDE Threat Modeling & CIS AWS Foundations Benchmark (v3.0.0)
* **Detailed Report**: [docs/threat-model.md](docs/threat-model.md)

### Data Flow Diagram & Trust Boundaries
* **Architecture Diagram**: [docs/tera%20diagram.png](docs/tera%20diagram.png)

### Summary of Assessed Threats
* **Total Threats Evaluated**: 12 across Identity, Network, Storage, and Supply Chain layers.
* **Critical Attack Vectors Mitigated**: Remediated public SSH exposure (Port 22), wildcard IAM administrative escalation, unencrypted data at rest, and unrestricted VPC default security groups.
* **Compliance Mapping**: Formally mapped against 12 core CIS AWS Foundations Benchmark controls with verifiable implementation evidence.
