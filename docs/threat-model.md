# 1. System Overview & Scope

## 1.1 System Description

The system under review is a Terraform-managed AWS secure baseline provisioned in `eu-central-1` (Frankfurt). The architecture consists of:

- An isolated Virtual Private Cloud (VPC, CIDR `10.0.0.0/16`) with DNS support and hostnames enabled.
- Segregated public (`10.0.1.0/24`) and private (`10.0.2.0/24`) subnets with automatic public IPv4 address assignment disabled.
- A locked-down default security group (all ingress and egress rules dropped) and an application-restricted security group with open public SSH access eliminated.
- Centralized VPC Flow Logs capturing all network traffic and streaming directly to secure object storage.
- A consolidated Amazon S3 bucket (`secure-baseline-data-*`) functioning as both operational storage and VPC Flow Log sink, protected by S3 Public Access Block, KMS encryption, versioning, and multipart lifecycle expiration.
- An IAM policy enforcing the Principle of Least Privilege (PoLP), strictly scoped to designated S3 read/write actions on the specific bucket ARN.
- Pre-deployment static application security testing (SAST) automated in GitHub Actions using Checkov and Terraform CLI verification.
### 1.2 Assets to Protect

- **Data at Rest**: Telemetry, VPC flow log records, and state objects stored in S3.
- **IAM Credentials & Access Tokens**: Administrative credentials, API keys, and service permissions.
- **Network Integrity**: Subnet perimeters, routing boundaries, and intra-VPC flow logs.
- **IaC Supply Chain**: Terraform codebase, CI/CD pipeline definitions, and GitHub Actions runner configurations.
### 1.3 Threat Actors

- **Anonymous Internet Threat Actors**: Automated scanning bots seeking exposed management ports (`0.0.0.0/0:22`) or publicly readable S3 buckets.
- **Compromised IAM Identities / Careless Insiders**: Authenticated accounts attempting privilege escalation, resource manipulation, or unauthorized data destruction.
- **Compromised CI/CD Dependencies**: Malicious pull requests or modified workflow scripts attempting to bypass Checkov static analysis.
### 1.4 Assumptions & Out-of-Scope Boundaries

- **Assumptions**: The underlying AWS hypervisor, physical infrastructure, and AWS Control Plane APIs are inherently trusted under the AWS Shared Responsibility Model.
- **Out of Scope**: Application-layer security (e.g., OWASP Top 10 web flaws) and OS-level patching within virtual machines, as no live EC2 instances or container workloads are provisioned in this baseline

## 2. Architecture & Data Flow Diagram (DFD)

The data flow diagram identifies system perimeters, communication vectors, and trust boundaries separating the Internet, GitHub CI/CD, and the AWS Cloud (refer to image in repo

### Trust Boundaries

- **Trust Boundary A (Internet Boundary - Untrusted)**: Separates external internet users from the AWS VPC network perimeter. Focuses on perimeter defense, public IP auto-assignment, and exposed ingress ports.
- **Trust Boundary B (AWS Account Boundary)**: Demarcates AWS Control Plane APIs and identity permissions from unauthorized external actors. Focuses on IAM policies, credentials, and API authorization.
- **Trust Boundary C (VPC Network Boundary)**: Encloses isolated VPC network space. Focuses on subnet isolation, default security group restrictions, and network traffic auditability.
- **Trust Boundary D (GitHub CI/CD Boundary)**: Separates source code and automated pipeline execution from production AWS environments. Focuses on code tampering, PR review enforcement, and pre-deployment SAST scanning
- ![[tera diagram.png]]

## 3. STRIDE Master Threat Register & Control Mapping

Risk Score Formula: $\text{Risk} = \text{Likelihood (1–3)} \times \text{Impact (1–3)}$.

- **High (6–9)** | **Medium (3–4)** | **Low (1–2)**

| **#**    | Component      | STRIDE Category                       | Threat Scenario                                                                                                                | L   | I   | Risk         | Implemented Control & Checkov ID                                                                                                                                                                                                                                     | Residual Risk & Architectural Rationale                                                                                                     |
| -------- | -------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | --- | --- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| **T-01** | Security Group | **Elevation of Privilege / Spoofing** | Open SSH (`0.0.0.0/0:22`) exposed to the internet allows remote brute-force or credential-stuffing attacks.                    | 3   | 3   | **9 (High)** | Removed open ingress; restricted ingress configuration (`aws_security_group.app_restricted`). Checkov: `CKV_AWS_24`.                                                                                                                                                 | Management planes must use AWS Systems Manager (SSM) Session Manager to remove direct listening ports entirely.                             |
| **T-02** | S3 Bucket      | **Information Disclosure**            | S3 bucket misconfiguration exposes sensitive data or flow logs publicly to unauthenticated internet actors.                    | 3   | 3   | **9 (High)** | Enforced all 4 flags on `aws_s3_bucket_public_access_block.data_pab`. Checkov: `CKV2_AWS_6`.                                                                                                                                                                         | Risk fully mitigated at bucket level; account-level S3 Public Access Block should be enforced as defense-in-depth.                          |
| **T-03** | IAM Policy     | **Elevation of Privilege**            | Wildcard statements (`Action: "*"` on `Resource: "*"`) permit full administrative takeover and unauthorized policy alteration. | 2   | 3   | **6 (High)** | Scoped actions (`s3:ListBucket`, `GetObject`, `PutObject`) to specific bucket ARN (`aws_iam_policy.scoped_s3_access`). Checkov: `CKV_AWS_62`, `CKV_AWS_63`, `CKV_AWS_286`, `CKV_AWS_287`, `CKV_AWS_288`, `CKV_AWS_289`, `CKV_AWS_290`, `CKV_AWS_355`, `CKV2_AWS_40`. | Policy applies to authorized identities; identity credential theft must be protected by account-level MFA and IdP controls.                 |
| **T-04** | S3 Bucket      | **Tampering**                         | Malicious insider or compromised identity overwrites or permanently deletes critical telemetry or flow log data.               | 2   | 3   | **6 (High)** | Enabled S3 object versioning via `aws_s3_bucket_versioning.data_versioning`. Checkov: `CKV_AWS_21`.                                                                                                                                                                  | S3 MFA Delete is not enabled on the versioned bucket (requires root credentials to configure).                                              |
| **T-05** | VPC Network    | **Repudiation**                       | Network compromise or unauthorized lateral traffic occurs within the VPC without an audit trail.                               | 2   | 2   | **4 (Med)**  | Enabled VPC Flow Logs capturing `ALL` network traffic to S3 (`aws_flow_log.vpc_traffic_log`). Checkov: `CKV2_AWS_11`.                                                                                                                                                | Flow logs have a 5–10 minute publishing aggregation window; real-time intrusion prevention (IPS) is not established.                        |
| **T-06** | S3 Bucket      | **Information Disclosure**            | Plaintext data at rest exposed to unauthorized entities through compromised physical storage blocks.                           | 1   | 3   | **3 (Med)**  | Enforced default Server-Side Encryption with AWS KMS (`aws:kms`) via `aws_s3_bucket_server_side_encryption_configuration.data_encryption`. Checkov: `CKV_AWS_145`, `CKV_AWS_19`.                                                                                     | S3 uses the default AWS-managed KMS key (`aws/s3`) rather than a customer-managed key (CMK) with custom rotation schedules.                 |
| **T-07** | VPC Subnets    | **Information Disclosure / Spoofing** | Subnets auto-assign public IPv4 addresses, exposing provisioned internal workloads directly to the web.                        | 2   | 2   | **4 (Med)**  | Disabled automatic public IP assignment (`map_public_ip_on_launch = false`) on `aws_subnet.public`. Checkov: `CKV_AWS_130`.                                                                                                                                          | Compute instances placed in public subnets can still receive public IPs if explicitly requested at launch time.                             |
| **T-08** | Default SG     | **Elevation of Privilege**            | Unmanaged default security group permits unrestricted lateral east-west communication between all associated instances.        | 2   | 2   | **4 (Med)**  | Adopted `aws_default_security_group.default` in Terraform with zero ingress and egress rules. Checkov: `CKV2_AWS_12`.                                                                                                                                                | New compute resources must be explicitly mapped to dedicated application security groups.                                                   |
| **T-09** | CI/CD Pipeline | **Tampering**                         | Insecure Terraform configurations bypass static security checks and get committed directly to repository `main`.               | 2   | 2   | **4 (Med)**  | Automated GitHub Actions pipeline running `terraform fmt -check`, `validate`, and Checkov SAST on every push and PR.                                                                                                                                                 | Branch protection rules requiring passing CI gates and signed peer reviews must be enforced in repository settings.                         |
| **T-10** | S3 Storage     | **Denial of Service (Cost)**          | Interrupted large uploads leave orphaned multipart binary fragments accumulating hidden storage charges.                       | 2   | 1   | **2 (Low)**  | Added lifecycle rule on `aws_s3_bucket_lifecycle_configuration.data_lifecycle` to abort incomplete multipart uploads after 7 days. Checkov: `CKV_AWS_300`.                                                                                                           | 7-day retention window leaves minor temporary billing liability.                                                                            |
| **T-11** | S3 Bucket      | **Denial of Service**                 | Catastrophic regional AWS data center disruption renders baseline storage assets unavailable.                                  | 1   | 2   | **2 (Low)**  | **Accepted Risk / Documented Skip (`CKV_AWS_144`)**: Cross-region replication omitted inline.                                                                                                                                                                        | Multi-region replication incurs ongoing inter-region data transfer fees and duplicate storage costs inappropriate for baseline demo assets. |
| **T-12** | S3 Bucket      | **Repudiation**                       | Lack of access logs for read/write requests made directly against the S3 data bucket.                                          | 2   | 1   | **2 (Low)**  | **Accepted Risk / Documented Skip (`CKV_AWS_18`)**: Server access logging omitted inline.                                                                                                                                                                            | Prevents recursive logging loops on a single-bucket architecture; access logs should target a dedicated external log-aggregation account.   |
### Risk Rating Justifications

- **Highest Risk (T-01, T-02 - Score 9)**: Exposing open administrative SSH or unauthenticated public S3 access guarantees discovery and automated exploitation by internet-wide port scanners within hours.
- **Lowest Risk (T-10 - Score 2)**: Orphaned multipart upload fragments do not breach confidentiality or integrity; they represent a minor, deferred billing inefficiency.

## 4. Documented Risk Exceptions (Checkov Skips)

In production cloud security engineering, security rules must be balanced against operational complexity and billing overhead:

1. **`CKV2_AWS_5` (Security Groups Attached to Resources)**:
    - _Status_: Skipped on `aws_security_group.app_restricted`.
    - _Justification_: This module establishes foundational network perimeters prior to compute deployment.
2. **`CKV_AWS_144` (Cross-Region S3 Replication)**:
    - _Status_: Skipped on `aws_s3_bucket.data`.
    - _Justification_: Multi-region replication doubles storage charges and introduces data egress fees unnecessary for baseline demo assets.
3. **`CKV_AWS_18` (S3 Bucket Server Access Logging)**:
    - _Status_: Skipped on `aws_s3_bucket.data`.
    - _Justification_: Directing access logs into the same bucket causes infinite logging loops. In enterprise setups, logs are shipped to a centralized Security Tooling AWS account.
4. **`CKV2_AWS_62` (S3 Event Notifications)**:
    - _Status_: Skipped on `aws_s3_bucket.data`.
    - _Justification_: The bucket does not publish events to downstream SNS/SQS event subscribers.
## 5. CIS AWS Foundations Benchmark (v3.0.0) Compliance Mapping

|**CIS Control ID**|**CIS Control Title**|**Applies?**|**Status**|**Implementation Evidence**|
|---|---|---|---|---|
|**1.16**|Ensure IAM policies are attached only to groups or roles|Yes|**Met**|Scoped IAM policy created as a standalone resource (`aws_iam_policy.scoped_s3_access`) ready for role attachment; zero direct user attachments.|
|**1.22**|Ensure no IAM policies allow full administrative privileges|Yes|**Met**|Remediated wildcard policy (`CKV_AWS_62`); scoped strictly to specific S3 read/write actions on the designated bucket ARN.|
|**2.1.1**|Ensure S3 Bucket Policy is not open to all accounts/public|Yes|**Met**|`aws_s3_bucket_public_access_block` enforces `block_public_policy` and `restrict_public_buckets`.|
|**2.1.2**|Ensure S3 Buckets are configured with Public Access Block|Yes|**Met**|Configured all four flags to `true` on `aws_s3_bucket_public_access_block.data_pab`.|
|**2.1.3**|Ensure S3 bucket access logging is enabled|Yes|**Not Met (Exception)**|Documented skip (`CKV_AWS_18`); single-bucket demo avoids recursive log loops. Requires central logging account.|
|**2.1.4**|Ensure S3 buckets are encrypted with Server-Side Encryption|Yes|**Met**|Enforced default encryption using `aws:kms` via `aws_s3_bucket_server_side_encryption_configuration.data_encryption`.|
|**2.1.5**|Ensure S3 bucket versioning is enabled|Yes|**Met**|Enforced versioning status `Enabled` via `aws_s3_bucket_versioning.data_versioning`.|
|**3.1**|Ensure CloudTrail is enabled across all regions|No|**Not Applicable**|Account-level governance control; outside the scope of this baseline networking/storage Terraform module.|
|**3.9**|Ensure VPC flow logging is enabled in all VPCs|Yes|**Met**|Flow log configured via `aws_flow_log.vpc_traffic_log` capturing `ALL` network traffic to S3.|
|**4.1**|Ensure no security groups allow ingress from 0.0.0.0/0 to port 22|Yes|**Met**|Removed open SSH rule from baseline security groups (`CKV_AWS_24`).|
|**4.2**|Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389|Yes|**Met**|Baseline security groups define no RDP port 3389 rules.|
|**4.3**|Ensure the default security group restricts all traffic|Yes|**Met**|Adopted `aws_default_security_group.default` with no ingress or egress rule blocks (`CKV2_AWS_12`).|
## 6. Residual Risks & Engineering Roadmap

1. **AWS Systems Manager (SSM) Integration**:
    
    - _Current State_: Ingress port 22 is eliminated, but administrative host connectivity is not yet established.
    - _Next Step_: Provision EC2 instance profiles with `AmazonSSMManagedInstanceCore` to enable zero-ingress terminal sessions over AWS SSM.
2. **Customer-Managed Encryption Keys (KMS CMK)**:
    
    - _Current State_: S3 uses AWS-managed KMS encryption (`aws/s3`).
    - _Next Step_: Deploy a dedicated `aws_kms_key` resource with automated annual key rotation and custom IAM key policies to prevent cross-account key sharing.
3. **Terraform Remote State Architecture**:
    
    - _Current State_: Terraform runs with local backend state.
    - _Next Step_: Configure remote backend using an encrypted S3 bucket and DynamoDB state locking table (`aws_dynamodb_table`) to eliminate race conditions and state file leakage.
4. **CI/CD Supply Chain Hardening**:
    - _Current State_: Checkov scans on every push and pull request.
    - _Next Step_: Configure GitHub branch protection requiring passing CI checks and mandatory signed peer reviews before merging into `main`.
