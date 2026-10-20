# S2 design: recorder and masker

| | |
|---|---|
| **Status** | Draft for the CTO's approval, 20 Oct 2026. No code is written until the CTO approves this design and the open decisions in §17. |
| **Stage** | S2 of the delivery re-plan v1.2 (`Globalsat-Group/IWS`, `docs/delivery/DELIVERY_REPLAN.md`) |
| **Review** | The masker is on the CTO's mandatory line-by-line review list (re-plan §3.3; `CLAUDE.md`). So are the gateway signer core, Terraform, IAM, the import-linter contracts and the leak tests this design proposes. |
| **Sources** | Re-plan §3.1–3.5, §4 (S2, S3), §8.1–8.3, §8.6, §10. Phase 1 plan (`docs/phase1-iws-app/IWS_APP_PLAN.md`) §1.3, §4.2, §4.6. Annex D (`annexes/D_platform_architecture.md`) §1, §2.1–2.9, §6. Annex E §1.4, §2.2, §2.3, §5. Annex F §6, §7. IWS catalog (`docs/iws-catalog/`): `objects.md`, `methods_provisioning.md`, `methods_reporting.md`, `enums.md`, `overview_workflows_rules.md`, `reports_library.md`, `ux_questions.md`. This repository: `CLAUDE.md`, `pyproject.toml`, `tests/test_import_contracts.py`, `licensing/`, `src/airtimesat_platform/`, `infra/terraform/modules/{secrets,network,kms}`, `infra/terraform/envs/sandbox`, `docs/SETUP_CHECKLIST.md`. |
| **Confidentiality** | The IWS catalog derives from confidential Iridium documentation. This document names IWS methods and fields only. It copies no descriptions. Keep it in this private repository. |

Conventions: *Inferred* marks an estimate or a design choice with no calibrated source. "Uncertain" marks something the sources do not settle. Every example value is fake and shows the surrogate format, never a real identifier.

## 1. Goal, scope and non-goals

**Goal.** Let AI agents run and debug IWS calls against SITEST without ever seeing a real identifier, holding an IWS secret, reaching Beta or production, or writing outside a CTO-approved test plan. The masker is the only path from agents to SITEST (re-plan §3.4). SITEST is refreshed from production, so it is treated as production personal data (Phase 1 plan §0, finding 8; §4.2).

**What S2 delivers.**

| Part | S2a: read path (opens agents for S3) | S2b: write guard (before ST-04) |
|---|---|---|
| Agent endpoint | HTTPS, CTO-minted session tokens (§3) | Same |
| Method policy | Read allowlist; always-refused list; default deny (§4) | Plan-gated write allowlist; DEACTIVE hard block (§8) |
| Masking | Consistent pseudonymization of every identifier in every allowed response (§5, §6) | Unmasking of identifiers in write requests, scoped to test inventory (§7) |
| Recorder | Call log of every agent call, masked only (§9) | Same, plus plan and idempotency records |
| Concurrency | One IWS permit at most, shared permit ledger (§10) | Same |
| Leak gate | Detectors, per-shape tests, fixture scan, runtime block and alarm (§11) | Request-side detector for writes |
| IWS access | The gateway signer core, built in S2 and used through `gateway.sitest_port` (§12) | Same |
| Infrastructure | Terraform modules, never applied by agents (§14) | Same |

The re-plan's S2 exit is unchanged: leak tests green on recorded samples, and the CTO has reviewed the code line by line (§15). This design splits S2 in two so agents can start read-only S3 work as soon as S2a passes. S2b must pass before ST-04 (polymorphic write and the SBD lifecycle, Annex F §7.2), the first spike test that writes.

**What waits for S3 or later.** The full operation registry for all 177 methods and the CI rule on unclassified WSDL operations (Annex D §2.1); the typed client and xsdata bindings (ST-01); lanes, aging, breaker and fault normalization (Annex D §2.4–2.7); the gateway service itself and its production endpoint (S4); HA (deferred, D2); the evidence module (S4); masking of raw-usage rows and inline report rows (open decision §17 #6); the spike-test harness, if approved (§12.4).

**Non-goals.** No production. No Beta, ever (Beta is CTO-only; CTO decision, 20 Oct 2026). No DEACTIVE through the masker. No real CDRs, TAP files or customer exports. No unmasking service for agents. No bulk export of SITEST data (enforced by row caps and daily budgets, §4.2, §10). No UI. No HA.

## 2. Threat model

### 2.1 Assets

| Asset | Why it matters |
|---|---|
| SITEST IWS secret | One development credential covers SITEST **and Beta** (decision, 20 Oct 2026). A leak of the SITEST secret is also a leak of Beta access. Iridium's rotation procedure and lead time are not known yet (re-plan §11.1 Q4; Annex B Q24). |
| Personal data in SITEST | A copy of production: IMEI, ICCID, IMSI, MSISDN, names, emails, vessel contacts, locations (Phase 1 plan §4.6, "Personal data and PIN"). |
| Write capability | Writes change SITEST state. DEACTIVE is irreversible: SIMs are not recycled, MSISDNs and IPs go into 60-day quarantine (catalog `overview_workflows_rules.md`, Rules). Test inventory is scarce: about 3 full runs are requested (re-plan §11.1 Q10). Some writes act on every matching contract in the SP (`manageDestinations`; Phase 1 plan §4.6). |
| The two IWS permits | A third concurrent request is rejected (catalog Rules; Annex D §2.4). Agent load can starve the CTO's own calls or a certification dry run. |
| Masking keys and the vault | The vault maps surrogates back to real values. Whoever reads it can de-pseudonymize everything agents have seen. Numeric types have little entropy (an IMEI with a known TAC has about 10^6 candidates, *Inferred*), so `K_mask` alone lets an attacker rebuild their mapping by brute force: a `K_mask` compromise equals a vault compromise for those types. |
| IWS signatures | The signature covers only the operation name and the timestamp (catalog signature algorithm). A leaked (operation, timestamp, signature) triple can be replayed with any body against SITEST or Beta within IWS's clock-skew tolerance, which is still unknown (Annex D open questions). |
| Agent session tokens | A token grants masked reads, and plan-scoped writes, until it expires. The agent proxy terminates TLS, so the token and masked data are visible to the proxy layer. |
| Recordings and call log | Masked, but still pseudonymized personal data while the vault exists. Agent transcripts held by the agent provider contain masked data too (§9). |
| Certification evidence | The evidence must match the `getIwsRequests` extract one to one (Annex E §2.3). Agent calls mixed into a certification window would break that. |

### 2.2 Actors and what each failure would leak or break

| Actor | Can do | Worst outcome without controls | Controls (section) |
|---|---|---|---|
| **Honest agent** (bugs, loops, misunderstandings) | Call allowed methods with a valid token | A wrong write on the wrong line; permit starvation; a masked fixture that still holds a real value committed to git | Plan-gated writes, dry run, idempotency (§8); rate limits and one permit (§10); fixture scan and runtime detector (§11) |
| **Prompt-injected agent** (instructions hidden in a repository, a web page, or a free-text field in SITEST data such as a vessel name or `spReference`) | Anything its token allows, chosen by the attacker | Exfiltrating real identifiers by enumeration or echo; DEACTIVE; SP-wide writes; reaching Beta | Vault-only unmasking; guesses alarm and daily budgets cap reads (§6, §7, §10); request-side detector (§11); always-refused list and hard blocks in code (§4, §8); no Beta endpoint anywhere the masker can load (§13); free text is tokenized as a whole value unless it matches a reviewed template (§6.1), which also removes most injection text |
| **Compromised agent session** (an attacker holds the session and its token) | Same as above, until the token expires or is revoked | Masked data for up to the token lifetime, within the token's read scope and daily budgets; writes inside one approved plan | Short tokens (§17 #12), revocation and kill switch (§3, §14); read scopes and budgets (§3.3, §10); no IWS secret or AWS credential in the session; writes need a plan the CTO signed (§8) |
| **Compromised masker process** (an exploit in XML parsing, or a malicious dependency) | Whatever the masker task can do | The vault and keys; SITEST calls through its own permit; with an in-process signer, the SITEST secret, which also works on Beta, returned in a response to an agent | Egress only to VPC endpoints and the SITEST addresses (§3.2); no shared VPC, database or role with anything that holds a production credential (§3.1); signer isolation (§17 #17); reviewed image pinned by digest (§14.3) |
| **The CTO** (trusted, part-time, fallible) | Everything | Pasting the credential into a session; approving a broad plan; running parallel manual calls that collide with the masker; leaving agents on during a certification run | Credential only in the interim store (Keeper recommended; the decision is due, S0 pack §7) and Secrets Manager; plan format with expiry and signed inventory (§8); permit policy that leaves one slot free (§10); automatic pause in certification windows (§9) |
| **Someone with AWS access** (the future deputy, a misconfigured role) | Read AWS resources | Reading the secret, the vault or recordings | Secret policy denies every reader but the masker role (existing `modules/secrets`); vault values encrypted with a KMS-wrapped key; read alarms (§13, §14) |

## 3. Architecture

### 3.1 Where it runs

The masker runs in Globalsat's AWS account, in the gateway VPC (`modules/network`), next to where the gateway will run (re-plan §3.4). Region: the same as the gateway, decided by ST-15. ST-15 needs only the AWS account and no credential, so the CTO runs it before the first masker deploy and the masker never has to move (§15.2).

The masker never shares a VPC, an RDS instance or a database role with anything that holds a production credential (§17 #14). Until S4, the masker security group has no path to any gateway port. The ALB gives this VPC its first inbound path from the internet, authenticated by token; the network module's header ("egress only, no inbound from the internet") and its invariant are updated to say so (§14.3).

```text
 Agent session (claude.ai cloud)                Globalsat AWS account (gateway VPC)
 ┌────────────────────────────┐   HTTPS 443    ┌──────────────────────────────────────────────┐
 │ agent code + session token │ ─────────────▶ │ ALB (public subnets, TLS)                     │
 │ allowlist: masker host     │                │   │                                           │
 │ (no *.iridium.com)         │                │   ▼                                           │
 └────────────────────────────┘                │ masker task (private subnet, no public IP)    │
                                               │   token check → policy → unmask request       │
                                               │   → permit (Postgres) → gateway signer core   │
                                               │   → mask → detect → record → respond          │
                                               │   │            │            │                 │
                                               │ Secrets Mgr  RDS Postgres  S3 recordings, KMS │
                                               │ (SITEST only) (vault, log,  (masked only)     │
                                               │               permits)                        │
                                               │   │ egress: SITEST via NAT; AWS via endpoints  │
                                               └───┼──────────────────────────────────────────┘
                                                   ▼ HTTPS 8443
                                          iwstraining.iridium.com (SITEST) only
```

### 3.2 Network path to SITEST (egress only)

- The task runs in a private subnet with no public IP. It reaches SITEST through the existing NAT gateway and its Elastic IP, the IP Iridium may later be asked to allowlist (re-plan §8.2).
- The SITEST endpoints are `iwstraining.iridium.com:8443`, paths `/iws-current/iws` (provisioning) and `/iwsReport-current/iws-report` (reporting) (catalog Rules; Annex D §1). **The current network module allows TCP 443 only** (NACL rules and the gateway security group). The masker needs TCP 8443 out. Annex D's diagram also says "8843 to be confirmed"; the catalog says 8443. The Terraform change opens 8443 only, in both NACLs (the private one and the NAT subnet's) and in the masker security group (§14.3).
- **AWS APIs only through VPC endpoints.** The masker has no 443 path to the internet. It reaches AWS only through interface endpoints (KMS, Secrets Manager, CloudWatch Logs and monitoring, ECR api and dkr) with private DNS and endpoint policies limited to this account (`aws:ResourceAccount`, `aws:PrincipalAccount`), and S3 through the gateway endpoint, whose policy allows only the recordings bucket and the ECR layer bucket. Masker security-group egress: 443 only to the endpoint security group and the S3 prefix list; 8443 only to the reviewed SITEST addresses. This closes the paths a compromised process would use: any IP literal on 443, DNS over HTTPS to a public resolver, attacker-controlled AWS host names and foreign S3 buckets (red-team case §11.5 #17).
- A Route 53 Resolver DNS firewall on the VPC answers only the SITEST host and the exact AWS endpoint names the masker uses, never a wildcard such as `*.amazonaws.com`; every other name, Beta and production included, gets no answer (§13.3).

### 3.3 How agents in a cloud coding session reach it

The agent session runs in Anthropic's cloud. Its egress goes through an agent proxy with a domain allowlist, and its source IPs are not Globalsat's to know or pin. So network location cannot authenticate it; a credential must.

| Option | How it works | For | Against |
|---|---|---|---|
| **A. HTTPS endpoint + CTO-minted session tokens** (recommended) | Public ALB with TLS on a Globalsat subdomain. Each request carries a short-lived token signed by a KMS key that only the CTO's role can use. The masker verifies it before any other work | Simple for agents (one header). No AWS credential in the session. Scoped (read scopes, plus one plan for writes). Short-lived and revocable. Works with any agent proxy | A public endpoint exists; it must reject unauthenticated traffic cheaply. The token is a bearer credential the agent holds, and it is visible to the agent proxy layer, which terminates TLS |
| B. Mutual TLS | ALB or API Gateway verifies a client certificate | Binds the client to a key | Likely infeasible: the agent proxy terminates TLS, so the client certificate cannot reach the ALB. The client key is still a bearer secret in the session. Longer-lived; revocation and rotation are harder. More setup for one person |
| C. Tunnel (SSM, a VPN or a tunnel service) | The session opens a tunnel into the VPC | No public endpoint | Needs tunnel software and more allowed hosts in the session. Long-lived tunnel credentials. A tunnel into the VPC widens what a compromised session can reach |
| D. AWS SigV4 with short STS credentials | API Gateway with IAM auth; the CTO hands the session temporary credentials | Native AWS auth | Puts AWS credentials in the agent session. A policy mistake widens them. Re-plan §8.2 allows no long-lived keys and uses GitHub OIDC for CI; temporary STS credentials in an agent session would be a new exception |

**Recommendation: A.** Details:

- **Token.** A compact JWS signed with a KMS asymmetric key (`kms:Sign` only for the CTO's mint role, used with MFA). The masker accepts only ES256 with the pinned key id, and ignores `jku`, `x5u` and `jwk` headers. Tokens carry a fixed prefix (`gsm_`) so gitleaks and GitHub secret scanning can find them (§11.3). Claims: `sub` (the label of the cloud environment), `scope` (`read:catalog`, `read:inventory` or `read:sp`, plus `write:<plan-id>` for writes; §4.2, §17 #19), `iat`, `exp` (§17 #12), `jti`, and rate tier. The masker caches the public key for at most 60 s. It checks signature, expiry, scope and the revocation list (`jti` denylist and a global "not before" time, read from the database) on every request, and fails closed if that read fails. It logs the source IP per `jti`.
- **Minting.** The CTO runs `masker-admin mint` from a trusted machine or AWS CloudShell. It never runs in an agent session.
- **Delivery to the session.** Cloud-environment secrets and variables apply to the whole environment: every new session in it picks them up. So agents use a **dedicated cloud environment for SITEST work**, and `sub` names that environment. The CTO sets the token there, preferably as a Network secret bound to the masker host, if that injects the header at the proxy without exposing the value to the session (to verify); otherwise as the environment variable `MASKER_TOKEN`. Never in chat, a document, git or a log. The platform `CLAUDE.md` forbids agents to hold credentials, so §12.3 adds this token to it as the one exception.
- **Unauthenticated traffic.** Rejected with a bare 401 before any parsing; only the health check `/healthz` is exempt and returns 200 with no body. An AWS WAF rate rule caps abuse; it is on by default (§14.3; cost in §14.2).
- **Agent environment network allowlist.** The dedicated environment must allow the masker's host name on 443 (for example `masker.<globalsat-domain>` [FILL: subdomain]; open decision §17 #11) and only the package-manager hosts its setup needs; whether the allowlist can be narrowed further after setup is to be checked in the environment settings. It must **not** allow `*.iridium.com`, including the WSDL Explorer host, so a session has no direct path to IWS even by mistake. Only the CTO changes the environment's network settings.

## 4. Agent interface

### 4.1 Request and response shapes

The masker speaks the same shape as the gateway's internal interface (Annex D §2.1; Annex F §6.2): a SOAP 1.2 envelope whose `<request>` carries no authentication fields, plus headers. Agents can then point the clients they build at the masker now and at the gateway later.

**Request.** `POST /iws/sitest/{provisioning|reporting}` with:

| Part | Content |
|---|---|
| `Authorization` | `Bearer <session token>` |
| Body | SOAP 1.2 envelope; the body's root element is the operation (exact WSDL case); `<request>` without `iwsUsername`, `signature`, `timestamp`, `serviceProviderAccountNumber`, `caller` or `callerPassword`. Validated against the WSDL schema before any policy check (§7). Identifiers are surrogates (§6). Maximum 256 KB (*Inferred*) |
| `X-SP` | Optional SP constant (`SP-0001`…, §6.2); the masker maps it to one of the SP account numbers held in the secret, since Globalsat may have several (Annex D §2.9). Absent: the default SP |
| `X-Correlation-Id` | Agent's own id, limited to `[A-Za-z0-9-]{1,64}`, echoed back |
| `X-Deadline` | Optional; capped by the method's timeout |
| `X-Test-Plan` | Required for writes (§8) |
| `X-Idempotency-Key` | Required for writes (§8) |
| `X-Dry-Run` | `true` validates and shows the final masked request without sending (§8) |

**Response.** The masked SOAP response or fault, element for element, so agents see the real shape (`xsi:type`, nil versus absent, empty success). Headers: `X-Masker-Call-Id`, `X-Masker-Decision` (`sent`, `dry-run`, `refused`, `blocked`, `busy`, `unknown`), `X-Masker-Permit-Wait` (bucketed: `0`, `<1s`, `<10s`, so it does not reveal when others use IWS), `X-Masker-Iws-Ms`, `X-Masker-Dropped` (count of elements the policy removed), and `Cache-Control: no-store` on every response. No IWS HTTP header or cookie is forwarded.

**Refusals** come back as a SOAP fault whose detail holds a masker element, never an IWS one, with an HTTP status: `401` bad token; `403` method not allowed, always refused, plan missing or not covering the request, identifier not issued; `409` idempotency conflict; `413` too large; `422` request failed schema validation or policy (for example a real-looking identifier in a free-text field); `429` rate limit or budget spent; `503` with `Retry-After` for `IWS_BUSY` (Annex D §2.4); `502` masking blocked by the runtime detector or any masking-stage failure (§11.4). `IDENTIFIER_NOT_ISSUED` also covers an issued surrogate outside the token's read scope, by the same code path and before any IWS call, so the answer does not reveal which surrogates exist. Each refusal has a stable code, such as `ALWAYS_REFUSED_DEACTIVE`, `ALWAYS_REFUSED_BULK`, `METHOD_NOT_ALLOWED`, `PLAN_REQUIRED`, `IDENTIFIER_NOT_ISSUED`, `MASKING_BLOCKED`.

**Small JSON endpoints:** `GET /v1/session` (scope, expiry, remaining budgets), `GET /v1/methods` (the allowlist with class, endpoint and limits), `GET /v1/calls/{id}` (the caller's own call-log row, without the request hash; ownership is checked against the token's `jti`, and call ids are random UUIDv4). Masked exchanges are not readable through the masker: its role can only `PutObject` them (§9). There is no endpoint that resolves a surrogate to a real value.

Example (fake values): the agent sends `getSubscriberAccount` with `<accountNo>SUB-9004217</accountNo>`. The masker resolves the surrogate in the vault, sends the real account number to SITEST, and returns the account with `imei` `990000000318651`, `sim` deviceNumber `9900000007582043714`, `msisdn` `990000058306`, and `createdBy` `user-k3f9q2m7`. Each type is derived independently, so the surrogates of one account share no digits (§6.3).

### 4.2 Method allowlist

Default deny: a method not listed below is refused. The lists are code constants with tests, reviewed line by line; they are not configuration.

**Reads (S2a), by read scope.** Drawn from the checklist v1.7 methods (Annex E §2.2) and the spike experiments (Annex E §1.4). System and catalog methods need `read:catalog`. Lines, devices, queue and log methods need `read:inventory` (results limited to signed test inventory and derived accounts; other rows are removed before masking and counted) or `read:sp` (SP-wide, with a lower budget; §10, §17 #19).

| Group | Methods | Limits |
|---|---|---|
| System | `authenticatedPing`, `getSystemStatus` (both endpoints), `getProjectVersion` (both), `findServiceProviderProfile`, `getDemoAndTrialCounts` | — |
| Catalog cascades | `getDemoAndTrialBundles`, `getPromoBundles`, `getSBDBundles`, `getM2MBundles`, `getVoiceBundles`, `getDataBundles`, `getVCSBundles`, `getDataSpeeds`, `getCommitmentPeriods`, `getLanguages`, `getLanguageChoices`, `getBundle`, `getServicePlans`, `getServicePlan`, `getSubmarkets`, `getModels`, `getModel`, `getManufacturers`, `getVerticals`, `getRudicsGroups`, `getAirlines`, `getFlagStates`, `getPrepaidPlans`, `getVoucherDenominations`, `getEvoucherInventory`, `getSecondaryDataServices`, `getBurstDeviceBundles`, `getBurstServiceBundles`, `getBurstSubscriptionNames`, `getBurstBroadcastCoverageAreas`, `getProgrammableButtons`, `getLocalNumberRegions`, `getVesselTypes` | `getEvoucherInventory`: `limit` 1–50 |
| Lines and devices | `accountSearch`, `getSubscriberAccount`, `validateDeviceString`, `getDevices`, `searchSimLock`, `getRechargeHistory`, `getPrepaidAccountDetail`, `getSubscriberOrganizations`, `getSubscriberOrgDetail`, `getVessels`, `getVessel`, `bulkActionSearch` | Every limit is a required inclusive range. `accountSearch`: `limit` 1–50, `startRow` ≤ 200 (*Inferred*), no `SMART` filter, `filterCond` `EQUALS` or absent, a filter required unless the token has `read:sp`. `getDevices`: `numResults` 1–20 (0 means all to IWS). `getRechargeHistory`: `limit` 1–50. `getSubscriberOrganizations`: an issued `Id` only. `getVessels`: `id`, `imo`, `mmsi` or a full issued `Vessel-` surrogate, never a name prefix. `bulkActionSearch`: by `bulkRequestId` only. Search inputs follow §7 step 8 |
| Queue and IWS log | `getQueueEntries`, `getQueueEntry`, `getIwsRequests`, `getIwsRequest` | Window ≤ 24 h, `Limit` 1–100. Only entries whose `caller` starts with `agent.` are returned (and, after §17 #5, whose `requestUser` is the agent user); the rest are removed before masking and counted. `getIwsRequest` and `getQueueEntry` refuse ids that no agent call produced (the call log maps IWS request ids to call ids). `getQueueEntries.createdBy` is set by the masker (§7 step 8). Embedded XML handling in §6.4 |
| Reporting metadata | `getReportTypes`, `getReportCategory`, `getReportColumns`, `getReportParameters`, `getReportPlanNames`, `getUsageUnits`, `getUsageCallTypes` | — |

A list response with more rows than the request allowed is blocked (§11.4). Names in these lists are catalog names. The code constants use the WSDL operation names (for example `getSubscriberOrgs`, `getEVoucherInventory`; Annex D §2.2), and a test asserts that every allowlisted and refused name exists in the WSDL snapshot.

`getAccountPoolingGroups` and `getAccountPoolingGroup` need `caller` plus `callerPassword` of a technical SPNet user (Phase 1 plan §1.3). The masker holds no SPNet password, so they stay refused until the CTO decides otherwise.

**Writes (S2b), only with a `write:<plan-id>` token and a matching plan (§8):** `activateSubscriber` (`bulkAction` `FALSE` or absent), `accountUpdate` (no status change; no change to `sim`, `imei`, `msisdn` or `ip`; §8.2), `setSubscriberAccountStatus` (to `SUSPENDED` or `ACTIVE` only; `bypassQuarantine` absent or `FALSE`), and, only for services sold, `rechargePrepaidAccount`, `subscribeBurstService`, `unsubscribeBurstService`. Device swaps wait for a CTO-confirmed class (§4.3, §17 #21).

### 4.3 Always refused

| What | Why |
|---|---|
| DEACTIVE in any form: `setSubscriberAccountStatus` with `newStatus` `DEACTIVE` or `CLOSED`; any `accountStatus` change through `accountUpdate` | DEACTIVE stays with the CTO (re-plan §3.4). `CLOSED` is terminal too (catalog `methods_provisioning.md`, `setSubscriberAccountStatus`); treated the same (open decision §17 #7) |
| Beta and production | No such endpoint exists in the masker's code, configuration or DNS (§13.3) |
| Unknown methods, wrong case, body root not matching the path's endpoint, an agent-supplied SOAP 1.2 `action` that differs from the root element, authentication fields in the request | Default deny; the operation comes from SOAPAction and must equal the body's root element (Annex D §2.1). The masker sets the outgoing action itself (§8.5) |
| SP-wide writes: `manageDestinations`, `sbdDestinationSearchReplace`, `sbdMOQueuePurge`, `updateEmailNotification` | The first three act on every matching contract (Phase 1 plan §4.6); `updateEmailNotification` acts at SP level (catalog), refused by design choice |
| Bulk: `bulkAccountUpdate`, `bulkAddPrepaid`, `bulkDeletePrepaid`, bulk `associateSimToImeiDevice`, bulk `deviceTransferOwner`; `activateSubscriber` with `bulkAction` `TRUE`, any `*BulkDetails` element, or a `BULK` literal in a device field (`ALWAYS_REFUSED_BULK`) | Cannot be scoped to test inventory; no bulk DEACTIVE (re-plan §8.1) |
| Destructive or inventory-moving: `deletePrepaidAccount`, `deactivateTelephonyScratchCard`, `unquarantineDevice`, `deviceTransferOwner`, `loadIMEI`, `restrictedSimSwap`, `associateSimToImeiDevice`, `disAssociateSimFromImeiDevice` | Irreversible or outside test scope |
| Not in S2b: `accountUpdateDevices`, and any `accountUpdate` that changes `sim`, `imei`, `msisdn` or `ip` | A swapped-out device appears to go to `INACTIVE`, which needs Service Delivery to re-use, and released numbers and IPs go into quarantine (catalog `enums.md`; to confirm in ST-04). One swap can burn scarce inventory (§17 #21) |
| Credentials and users: `resetIWSUserPassword`, `resetUserPassword`, `userAuthenticate`, `findUserProfiles`, `createUserProfile`, `updateUserProfile`, `changeUserProfileStatus`, `unlockUser`, `getSPNetGroups`, `getSPNetPages`, `resetTelephonyVMPin` | Return or change secrets (Annex D §2.5, §2.8) |
| DIDWW: `addDIDWWNumberInventory`, `getDIDWWNumberInventory`, `removeDIDWWNumberInventory` | Need `callerPassword` and `didwwUserApiKey` |
| Money and vouchers: `orderScratchcards`, `activateScratchCards`, `activateTelephonyScratchCards`, `updateScratchCardStatus`, `refundPrepaidVoucher`, `getScratchcards`, `getScratchCardBatches`, `getScratchcardDeals`, `getScratchcardOrders`, `getScratchCardActivationStatus`, `searchVoucherOrder`, `getPrepaidAccountSummary`, `searchDeviceUsage` | Money writes, PINs in responses, or bulk personal data |
| Reports that leave the masker or return bulk rows: `createScheduledReport`, `updateScheduledReport`, `getScheduledReports`, `createOnDemandReport` (background mode always; inline mode in S2, open decision §17 #6) | Background reports are emailed to the requester with real data (Phase 1 plan §4.6); scheduled reports carry delivery credentials (Annex D §6) |
| Report job metadata: `getReportTransactionLog`, `getFileList` | No agent-created reports exist in S2, so they would only show other users' report activity (file and report names, parameters, error text, delivery addresses); revisit with §17 #6 |
| Raw usage: `getCertusRawUsage`, `getIOPRawUsage`, `getSBDRawUsageNew`, `getTelRawUsage`, `getSubscriberUsage` | CDRs with locations and called numbers; open decision §17 #6 |
| Configuration writes on the reporting endpoint (trackers, profiles, resource groups, comm status), `updateTopicAssociation`, `updateQueueEntry`, vessel writes, secondary data service writes, organization writes | Not needed for S2–S3; they push emails and names into SITEST |

## 5. Identifier inventory

Every field below carries a personal or account identifier, a secret, or free text. The treatment codes are defined in §6.1. Source files are in `Globalsat-Group/IWS`, `docs/iws-catalog/`: **[O]** `objects.md`, **[MP]** `methods_provisioning.md`, **[MR]** `methods_reporting.md`, **[RL]** `reports_library.md`, **[E]** `enums.md`, **[OW]** `overview_workflows_rules.md`. Field names follow the catalog; the live WSDL is the source of truth (catalog README), so the field map is regenerated from the WSDL in S2 (§12).

### 5.1 By identifier type

| Type | Fields: objects and methods | Report columns [RL] | Treatment | Notes |
|---|---|---|---|---|
| **IMEI** | [O] `accountSearchReportImpl.imei`; `devicePairImpl.deviceImei`; `deviceImeiImpl.deviceNumber`; `imei`/`Imei` on the Burst device, Certus, M2M+, OpenPort, PTT device, SBD and telephony base account objects; `pttDeviceDetailImpl.Imei`; Burst service `Subscribers`/`Subscriber.Imei`; `vesselLinkImpl.IMEI`; `sbdDestinationSearchReplaceEntryImpl.imei`; `voucherActivityImpl.imei`; `sbdmtActivityImpl`/`sbdmoActivityImpl` `imei`; `imei` in the bulk details `m2MBulkDetailImpl`, `sbdBulkDetailImpl`, `telephonyBulkDetailImpl`, `pttDeviceBulkDetailImpl`; `deliveryDestinationImpl.destination` when `deliveryMethod` is `IRIDIUM_DEVICE` (§5.2); `loadImeiErrorDetailImpl.device`; `imei` in `certusRawCallDataEntryImpl`, `iopRawCallDataEntryImpl`, `sbdRawCallDataEntryNewImpl`, `subscriberCallDataEntryImpl`, `telRawCallDataEntryImpl`. [MP] `loadIMEI` `Devices[].Device`; `deviceTransferOwner` `bulkDetails[].bulkDeviceString`; `searchSimLock.imei`; `subscribeBurstService.imei`, `unsubscribeBurstService.imei`; `associateSimToImeiDevice`/`disAssociateSimFromImeiDevice` `deviceImei`; `deviceTransferOwner.deviceString`; `validateDeviceString.deviceString`, `fromDeviceString`; `setSubscriberAccountStatus.value` when `updateType` is IMEI; `accountSearch.filterValue` and `details`. [MR] tracker `memberId` (`memberTypeEnum` IMEI); `updateResourceGroupMember.devices`; raw-usage criteria `value` (`resourceType` IMEI) | IMEI in Account Sync, Burst Service, Certus IMEI Registration, Certus IP Data Services, Certus Raw Usage, Device Destination, Device Setting Detail, M2M Device Search, MT Filter, OpenPort Raw Usage, SBD Device Search, SBD Raw Usage Summary and New, every Subscriber History and Subscriber Report except Paging, Subscriber Usage Summary, Telephony Raw Usage, Voucher Usage Details | T-NUM | 15 digits; SBD/M2M+ IMEIs start with 3 and end with 0 [OW]; no check digit assumed (catalog example IMEIs fail Luhn). `imeiProfileImpl.tac`/`fac` are model prefixes, kept |
| **ICCID (SIM serial)** | [O] `accountSearchReportImpl.iccid`; `deviceSimImpl.deviceNumber`; `devicePairImpl.deviceSim`; `sim`/`Sim` on Certus, OpenPort and telephony accounts; `vesselLinkImpl.Sim`; `prepaidAccountDetailImpl.iccid`; `m2MBulkDetailImpl.sim`, `telephonyBulkDetailImpl.sim`; `deviceSwapImpl.fromDevice`/`toDevice`; `restrictedDeviceSwapImpl.oldDeviceNumber`/`newDeviceNumber`; `iccid` in `subscriberCallDataEntryImpl`, `telRawCallDataEntryImpl`. [MP] `deletePrepaidAccount.iccid`, `getRechargeHistory.iccid`, `refundPrepaidVoucher.iccid`, `getPrepaidAccountSummary.subscriberitem` (MSISDN or SIM), `accountUpdateDevices.fromDevice`/`toDevice`, `accountSearch` (`SIM_SERIAL_NUMBER`), `setSubscriberAccountStatus.value` (SIM) | SIM (ICCID) in Account Sync, Certus, OpenPort and Telephony Raw Usage Summary, Pin Puk, Prepaid Account Summary, Subscriber History and Report (ATS, All, Certus, M2M, OpenPort, Telephony), Subscriber Usage Summary; SIM in Telephony Raw Usage; Pin Puk Start/End Range parameters | T-NUM | 19 digits [OW]. Check digit assumed Luhn (*Inferred*; verify on recordings) |
| **IMSI** | [O] `deviceSimImpl.imsi`; `voucherActivityImpl.imsi`; `imsi` in the Certus, IOP, subscriber and telephony CDR entries. [MP] `bulkAddPrepaid`/`bulkDeletePrepaid` `telephonyImsis`; `accountSearch` (IMSI). [MR] tracker and resource-group members (IMSI); raw-usage `resourceType` IMSI | IMSI in Account Sync, Certus, OpenPort and Telephony Raw Usage (and Summaries), Device Destination, Device Setting Detail, M2M Device Search, MT Filter, Pin Puk, Prepaid Account Summary, Resource Inventory, Subscriber History and Report (ATS, All, Certus, M2M, OpenPort, Telephony), Subscriber Usage Summary, Voucher Usage Details | T-NUM | 15 digits [OW] |
| **MSISDN and other numbers** (MSISDN-B/C, ISDNA, PLUS1/PLUS7, local numbers, follow-me) | [O] telephony base account `msisdn`, `msisdnb`, `msisdnc`, `plusNumber`, `localCountry`; M2M+ `msisdnc`, `msisdnb`; `deviceNumberImpl.deviceNumber`; `openPortDeviceNumberImpl.deviceNumber`, `plusOneNumber`; `certusDeviceNumberImpl.deviceNumber`, `localNumber`; Paging `isdna`, `followMePagingNumber`; `localCountryImpl.deviceNumber`; `prepaidAccountDetailImpl.msisdn`; `voucherActivityImpl.msisdn`; `deviceErrorImpl.deviceNumber`; `removeDIDWWErrorDetailImpl.device`. [MP] `msisdn` in `deletePrepaidAccount`, `getPrepaidAccountDetail`, `rechargePrepaidAccount`, `refundPrepaidVoucher`, `getRechargeHistory`, `resetTelephonyVMPin`; `unquarantineDevice.deviceNumber`; DIDWW `localNumber`; `validateDeviceString` (types in `deviceStringTypeEnum` [E]); `getDevices` `num` results | MSISDN in Certus, OpenPort and Telephony Raw Usage, Prepaid Account Summary, Prepaid Call History, Subscriber Usage Summary, Voucher Usage Details; Line N MSISDN and Line N Local Number in Subscriber History and Report (ATS, All, Certus, M2M, OpenPort, Telephony); FMP MSISDN, Plus Num and Number Details Array in Account Sync; MSISDNC in Device Destination, Device Setting Detail, M2M Device Search, MT Filter; ISDNA and Follow Me MSISDN in Subscriber History and Report Paging | T-NUM | MSISDN: 12 digits starting 8816/8817 [OW]. Other number formats undocumented (uncertain) |
| **Called and calling numbers** | [O] `voucherActivityImpl.calledNumber`; `certusRawCallDataEntryImpl.callingFrom`/`callingTo`/`dialedNumber`/`shortCode`; `iopRawCallDataEntryImpl.callingFrom`/`callingTo`; `subscriberCallDataEntryImpl.callingNum`/`calledNum`; `telRawCallDataEntryImpl.aNumber`/`bNumber`/`calledNumber`/`callingNumber` | Calling From, Calling To, Dialed Number, Short Code (Certus Raw Usage); Calling From/To (OpenPort Raw Usage); A Number, B Number, Called Number, Calling Number (Telephony Raw Usage); Called (Prepaid Call History); Called Number (Voucher Usage Details) | P-ONE | Only in refused methods in S2. Third parties' numbers, not just subscribers' |
| **Capcode** | [O] Paging `Capcode`; `deviceCapcodeImpl.deviceNumber`. [MP] `validateDeviceString` (CAPCODE); `setSubscriberAccountStatus.value`; `accountSearch` (CAPCODE) and `details` | Capcode in Account Sync; CapCode in Subscriber History and Report All; Capcode in Subscriber History and Report Paging | T-NUM | Format undocumented (uncertain). Paging is likely N/A (Annex E §2.2) |
| **IP addresses, hosts, subnets, VPN names** | [O] Certus and OpenPort `ip`/`Ip`, `publicIP`; `deviceIpImpl.deviceNumber`; `deviceNumberImpl.deviceNumber` (can be an IP); `deliveryDestinationImpl.destination` (typed by `deliveryMethod`, §5.2); `mtFilterImpl.address` (typed by `ruleType`, §5.2; wildcards); `sbdmoActivityImpl.Destination`; `moipQueueReportEntryImpl.deliveryTo`, `deliveryPort`; `secondaryDataServiceImpl.subnetValue` (and `subnetMask`, kept); `deviceApnImpl.vpnName`, `deviceApnImpl.deviceNumber` (VPN id, IP-like), `openPortSubscriberAccountImpl.vpnId` (T-STR); `outputSettingsEntryImpl.deliveryAddrs` when an FTP/SFTP host or S3 bucket (T-HOST), `deliveryPath` (T-STR); `ipAddress` in the Certus, IOP and subscriber CDR entries; SBD `d1..d5` `DeliveredTo`/`DeliveredToPort`. [MP] `sbdMOQueuePurge.address`, `sbdMOQueueReport.address`; `manageDestinations` `oldDestination`/`newDestination`; `sbdDestinationSearchReplace` `oldValue`/`newValue`; `getDevices` `ip` | IP Addr and Public IP (Account Sync); IP Address, Public IP Address, Data Network Name (Subscriber History and Report All, Certus, OpenPort); IP Address (Certus, OpenPort Raw Usage); Destination and Delivery Address N (Device Destination, Device Setting Detail, M2M Device Search, SBD Device Search, Subscriber History and Report SBD, M2M, All); Filter Address N (Device Setting Detail, MT Filter); Delivery N Destination/Port (SBD Raw Usage New) | T-IP, T-HOST, T-STR | Delivery destinations are customer servers or mailboxes. Ports kept. `deviceApnImpl.routingInfo` is an int, kept |
| **Contract and account IDs** | `SUB-` numbers: [O] `accountSearchReportImpl.accountNumber`; `subscriberAccountEntryImpl.subscriberAccountNumber`; `absSubscriberAccountImpl.subscriberAccountNumber`; `vesselLinkImpl.subscriberAccountNumber`; `pttDeviceDetailImpl.contractId`, `pttTalkgroupDetailImpl.contractId`; `rechargeHistoryEntryImpl.accountNumber`; `voucherActivityImpl.accountNumber`; `accountPoolingGroupImpl.memberAccounts`; `userImpl.preferredAccount` (uncertain: SP or contract); `accountNumber` in every CDR entry. [MP] `accountNo` (`getSubscriberAccount`, `accountUpdateHomeGateway`, `rechargePrepaidAccount`), `subscriberAccountNumber` (`accountUpdateDevices`, `restrictedSimSwap`), `resetTelephonyVMPin.accountNumber`, `setSubscriberAccountStatus.value` (`SUBSCRIBER_ACCOUNT_NUMBER`), `accountSearch` (`ACCOUNT_NUMBER`). Other IDs: `prepaidAccountDetailImpl.accountNo` (SIM account); voucher accounts with `SC-` prefix [OW]; pooling group `id` (`SHARED_GROUP` search [E]); `subscriberOrganizationImpl.id`, `refid`; `subscriptionOrgId`; `talkgroupId`; `pttTalkgroupDetailImpl.controllerId`; `vesselImpl.id`; resource group `resourceId`; `trackerMemberEntryImpl.memberId` | Contract ID (most reports); Account Number (Burst Service); Sub Account and Bill No (In/Out of Bundle); Group ID (Account Sync, Group Plan, Service Plan); Subscriber Org ID, Billing ID, Reference ID, Controller ID, Talkgroup ID; Vessel ID | T-NUM (`SUB-`, `SC-`), T-STR (others) | `SUB-XXXXXXX` format [MP `accountSearch`]. IWS's own operational IDs (`cdrId`, `sessionId`, `requestId`, `bulkRequestId`, `queueEntryId`, `transactionId`) are kept: they identify transactions, not people (uncertain for `sessionId`) |
| **SP identifiers** | [O] `serviceProviderAccountNumber`; `serviceProviderImpl.accountNumber`, `accountName`, `accountMgrId`; `spAccountNo`, `spName`, `spAccountNum` in CDR entries; `scratchCardsDetailEntryImpl.ownerSp`; `owner` (trackers, profiles, resource groups, comm status: SP account or `GLOBAL`); `baseQueueEntryImpl.serviceProviderNumber`, `serviceProviderName`; `VesselContactInfoImpl.spNum`; `userImpl` `accessInfo.spAcct`, `serviceProviderName`, `userAccessInfo.spPoid`; `simLockResultImpl.accountNumber` (SP account number [MP `searchSimLock`]); `accountPoolingGroupImpl` `spAccountNum`, `spAccountName`. [MP] `deviceTransferOwner.toSPAccountNumber`; `loadIMEI.restrictedSpAccountNumber`; `updateTopicAssociation.associatedSPAccountNumber`; `listTopics.apAccountNubmer`; `createSecondaryDataService.permittedProviderAccounts` | SP Account No / SP Account Number and SP Name (most reports) | C | Globalsat's own SP numbers, possibly several (Annex D §2.9). Constants per distinct real value. `plmnId` kept |
| **Person names and logins** | [O] `userImpl.username`, `userid`, `contactInfo.salutation`, `company`, `firstName`, `middleName`, `lastName`; `VesselContactInfoImpl.emergencyFirstName`, `emergencyLastName`, `lastSpUpdUser`; audit fields `createdBy`, `updatedBy` (account objects, queue entries, recharge history, trackers, reports, file lists); `iwsLogImpl.requestUser`, `caller`; `requestorId` (report details). [MP] `resetIWSUserPassword` `iwsUserName`, `iwsUserId`; `findUserProfiles.userName`, `userId`; `updateUserProfile.currentUserName`; `changeUserProfileStatus` `userId`, `username` (an email); `unlockUser.user`; `resetUserPassword` `username`, `userid`; `getQueueEntries.createdBy` | User Name (Certus IMEI Registration, every Subscriber History and Report, User Activity Report); Created By (Prepaid Account Summary) | P-ONE; the masker's own `caller` value is kept | SITEST is a production copy, so these are real Ops and customer staff logins. `iwsUsername` → C |
| **Organization, vessel and group names** | [O] `vesselImpl.vesselName`, `fleetName`; OpenPort metadata `vesselName`; `subscriberOrganizationImpl.organizationName`; `subscriberAccountEntryImpl.subscriberOrganization`; PTT talkgroup `Name`; `accountPoolingGroupImpl.name`; `rudicsGroupImpl` `name`, `description`, `group` (SP-specific, uncertain); `topicImpl.apName` (IMT owner name); Burst service `serviceName` (uncertain); resource group `groupName`; tracker `name`; rules profile `profileName`; tracker rule `name`; `accountSearch.details` when the filter is a vessel name | Vessel Name, Fleet Name, Subscriber Org Name, Org Name, Group Name | T-STR | Group, tracker and profile names may embed customer names (uncertain). Catalog names (bundles, plans, models, airlines) are kept |
| **Vessel and aircraft identifiers** | [O] `vesselImpl.imo`, `mmsi`, `callSign`, `portRegistry`; `atsSubscriberAccountImpl.icao`, `regTailNumber`; `atsSafetyInfo` `icao`, `regTailNumber`; `subscriberAccountEntryImpl.atsInfo` `icao`, `airlineRegistration`. [MP] `getVessels` search inputs; `validateDeviceString` (`ATS_ICAO`, `ATS_TAIL_NUMBER`); `accountSearch` (`IMO`, `MMSI`, `ATS_ICAO`, `ATS_REG_TAIL_NUMBER`) | IMO, MMSI, Call Sign, Port of Registry, Aircraft Registration, Aircraft ICAO, Aircraft Reg, ICAO | T-NUM (IMO, MMSI), T-STR (others) | Test or unknown MMSIs get a `T` or `U` prefix from IWS [O `vesselImpl`]. ATS is likely N/A (Annex E §2.2) |
| **Vessel quasi-identifiers** | [O] `vesselImpl.buildYear`, `personCapacity`, `vesselTon`, `shipRegistry` (flag state) | Build Year, Person Capacity, Vessel Ton, Nation Flag | D in S2 (G considered later) | Combined with type, dates and IDs they can single out a vessel through public registries. No S2–S3 test needs them |
| **Emails** | [O] `userImpl.contactInfo.email`; `VesselContactInfoImpl.emergencyEmail`; `confirmationEmailAddr` (`maritimeSafetyInfoImpl`, `vesselLinkImpl`); `trackerEntryImpl.emailAddresses`; `trackerEmailLogEntryImpl.emailAddresses`; `outputSettingsEntryImpl.deliveryAddrs`; `onDemandReportDetailsEntryImpl.deliveryAddrs`; email-type `deliveryDestinationImpl.destination` and `mtFilterImpl.address`; SBD `confirmAddress` (uncertain). [MP] `getEmailNotification.email`. [MR] `createTracker`/`updateTracker` `emailAddresses` | Delivery Address N, Destination, Filter Address N (when email); Download Confirm Address (SBD Raw Usage New, uncertain) | T-EMAIL | `deliveryAddrs` may hold an FTP address with credentials [MR `createOnDemandReport`] → D |
| **Phone numbers (contact)** | [O] `userImpl.contactInfo.phone`, `contactInfo.contactPhone` (soap-D name); `VesselContactInfoImpl.emergencyPhone` | — | P-ONE | |
| **Postal addresses** | [O] `userImpl.contactInfo.address`, `city`, `state`, `postalCode`; `country` kept | — | P-ONE; country kept | |
| **Serial numbers** | [O] `rechargeHistoryEntryImpl.serialNumber`; scratch-card `startSerial`/`endSerial`, `startSerialNumber`/`endSerialNumber`, `serialNumber`; `CertusScratchcardImpl.serialNumber`, `orderNo`; `burstSubscriptionResponseImpl.serialNumbers`; voucher serial ranges; Paging `mtd` (MTD serial); `purchaseOrder`. [MP] `deactivateTelephonyScratchcard.serialNumber`, `refundPrepaidVoucher.serialNumber`, `updateScratchCardStatus.scratchCardNumbers`, `getScratchcardOrders.serialNumber` | Serial Number (Account Sync, meaning uncertain; Scratch Card Details; Voucher Details and Usage Details); Serial (Prepaid Call History); Start/End Serial (Scratch Card Summary); PO Number (Voucher Details) | T-NUM (19-digit voucher serials and numeric-typed fields such as `orderNo`, a long), T-STR (others) | Voucher serial: 19 digits [OW] |
| **Locations** | [O] `location` in Certus and IOP CDR entries; SBD `latitude`, `longitude`, `cepRadius`, `locationType`, `isuDoppler`, `isuTiming`; `tzOffset`; `sbdmoActivityImpl` `latitude`, `longitude`, `cep`; `voucherActivityImpl` `lac`, `latMin`, `latPol`, `longMin`, `longPol`, `setAltitude`, `callingHC`, `callingVC`, `countryName`, `regionName`, `tZOffset` | Location (Certus, OpenPort Raw Usage); Latitude, Longitude, CEP Radius (SBD Raw Usage New); LAC, Latitude Min/Pol, Longitude Min/Pol, Altitude, Calling HC, Calling VC, TZ Indicator, Country Name, Region Name (Voucher Usage Details) | G (coordinates to 1 degree, *Inferred*); D (LAC, altitude, Doppler, timing) | Only in refused methods in S2 |
| **Free text** | [O] `subscriberAccountMetadata.spReference` (every account type); `description` (many objects); `statusDescription`; `errorMessage` (`iwsLogImpl`, `baseQueueEntryImpl`, `addDIDWWNumberInventory`); `VesselContactInfoImpl.otherInfo`; tracker `subject`, `body`, `emailBody`; email profile `msgSubject`, `msgBody`; pooling group `Description`; `returnMessage`, `Message`; SBD `metadata`; `outageReason` and outage `description`; `valid*DeviceDataImpl.reason`; `reportTransactionLogEntryImpl.internalErrorDescription`, `externalErrorDescription`; `serviceProviderImpl.messageText`; `userImpl.accessInfo.userPrefs`. [MP] `setSubscriberAccountStatus.reason`. SOAP fault reason and detail text | SP Reference (Account Sync, Subscriber History and Report, Subscriber Usage Summary); Description | F; `spReference` and customer-entered descriptions → T-STR (§6.4) | IWS echoes request values in error text (catalog error tables). `spReference` is searchable (`PROVIDER_REFERENCE` [E]), so it is reversible |
| **Other IDs and file names** | [O] Certus `messagingServiceDetail.cmid`; `deviceId` on every device object (`deviceCapcodeImpl`, `certusDeviceNumberImpl`, `deviceSimImpl`, `deviceImeiImpl`, `deviceNumberImpl`, `deviceIpImpl`, `localCountryImpl`, `deviceApnImpl`; uncertain: a billing resource id); `subscriberAccountEntryImpl.deviceDetails`; `topicImpl` `queueSetId`; `fileListEntryImpl.fileName`; `certusRawCallDataEntryImpl.sdfName`; `telRawCallDataEntryImpl.sourceNetwork` (uncertain); `sbdRawCallDataEntryNewImpl.mtFilename`. [MR] `getFileList.requestName` | Download File Name (SBD Raw Usage New); SDF Name (Certus Raw Usage) | T-STR | These match no pattern detector, so the field map is the only control (§6.5) |
| **Embedded payloads** | [O] `iwsLogImpl.request`, `response` (escaped XML); `baseQueueEntryImpl.request`, `response`; `reportResultDetailsEntryImpl.row` (CSV); `createOnDemandReport.link` [MR]; `fileListEntryImpl.fileDownloadURL` | Delivery Array, Filter Array (Account Sync); Devices Array, TalkGroup Array (IWS getSubscriberOrg) | N for XML, CSV and arrays; D for URLs | A download URL is a bearer link to the full report (Annex D §2.8) |
| **Secrets** (always dropped) | [O] `signature`, `callerPassword`, `didwwUserApiKey`, `userImpl.password`, `CertusScratchcardImpl.pin`, `scratchCardDetailsImpl.pin`, `scratchCardsDetailEntryImpl.pinNumber`, `prepaidAccountDetailImpl.pinNumber`, `captainPin`, `twoStagePin` (Certus voice line, OpenPort phone line, `twoStageImpl`), Burst `dpName`, `dpPassword`, `spName`, `spPassword` (the names are the logins paired with those passwords), `outputSettingsEntryImpl.deliveryUserKey`, `deliveryPwSecret`, `vesselImpl.gmdssPw` (uncertain). [MP] `resetIWSUserPassword.newPassword`; `resetUserPassword.Token`, `Password`; `userAuthenticate.password`; `resetTelephonyVMPin.newValue`; `updateTopicAssociation.associationKey` | Pin 1, Pin 2, Puk 1, Puk 2 (Pin Puk); PIN (Prepaid Account Summary, Voucher Details, Voucher Usage Details); Line N 2 Stage PIN, Line N Captain PIN (Subscriber History and Report) | D | Masked in Annex D §2.8 already; the masker removes them before anything else |

### 5.2 Identifier-typed parameters

Some fields are typed by a sibling enum, so their class depends on the request:

| Field | Typed by | Values that carry identifiers [E] |
|---|---|---|
| `accountSearch.filterValue`, response `details` | `filterType` (`subscriberAccountSearchTypeEnum`) | `ACCOUNT_NUMBER`, `ATS_ICAO`, `ATS_REG_TAIL_NUMBER`, `BURST_SERVICE`, `CAPCODE`, `DELIVERY_DEST`, `IMEI`, `IMO`, `IMSI`, `IP_ADDRESS`, `ISDNA`, `LOCAL`, `MMSI`, `MSISDN`, `MSISDNB`, `MSISDNC`, `MT_FILTER`, `PROVIDER_REFERENCE`, `PTT_TG`, `SHARED_GROUP`, `SIM_SERIAL_NUMBER`, `VESSEL_NAME`; `SMART` is refused. Without a filter, `details` defaults by service type (ICCID, IMEI, talkgroup ID, Burst service name or capcode) [MP] |
| `setSubscriberAccountStatus.value` | `updateType` (`statusChangeTypeEnum`) | `CAPCODE`, `IMEI`, `ISDNA`, `MSISDN`, `SIM`, `SUBSCRIBER_ACCOUNT_NUMBER` |
| `validateDeviceString.deviceString`, `fromDeviceString` | `deviceStringType` (`deviceStringTypeEnum`) | `ATS_ICAO`, `ATS_TAIL_NUMBER`, `CAPCODE`, `IMEI`, `IPADDR`, `ISDNA`, `MSISDN`, `MSISDNB`, `MSISDNC`, `PLUS1`, `PLUS7`, `SIM` |
| `deviceTransferOwner.deviceString` | `deviceStringType` | as above |
| Raw-usage criteria `value` | `resourceType` (`usageSubscriberSearchTypeEnum`) | `ACCOUNT_NUMBER`, `IMSI`, `IMEI`, `MSISDN`, `SIM_SERIAL_NUMBER` |
| Tracker `memberId`; resource-group members | `memberType` / `resourceType` | `MSISDN`, `IMEI`, `ICCID`, `IMSI`, `TALKGROUPID`, `GROUP` |
| `getDevices` results | `deviceType` (`deviceTypeEnum`) | `CAPCODE`, `IMEI`, `IP`, `ISDNA`, `LOCAL_NUMBER`, `NUM`, `PLUSONE`, `SIM`, `VOUCHER`, `VPN` |
| `searchDeviceUsage` criteria `value`; scratch-card search values | `searchType` | `ACCOUNT_NUMBER`, `IMEI`, `IP`; scratch-card `PIN` (refused method) |
| `sbdDeletePendingDownloads.value`; `searchVoucherOrder.searchCriteria` | `searchType` (`sbdSearchTypeEnum`; voucher order search type) | Refused methods; typed like the rows above when allowed |
| `deliveryDestinationImpl.destination` | `deliveryMethod` (`deliveryMethodTypeEnum`) | `IRIDIUM_DEVICE` → T-NUM (IMEI); `EMAIL` → T-EMAIL; `DIRECT_IP` → T-IP or T-HOST, port kept |
| `mtFilterImpl.address` | `ruleType` (`mtFilterRuleTypeEnum`) | `EMAIL` → T-EMAIL; `DOMAIN` → T-HOST; `IP_ADDRESS` → T-IP; wildcards kept |
| Report columns Delivery Address N, Destination N | Delivery Method N | As `deliveryDestinationImpl.destination` |
| Report column Resource ID | Resource Type (Resource Inventory) | `IP`, `CAPCODE`, `IMEI`, `ICCID`, `MSISDN` and the other number types [E]. In Group Plan there is no type column: pattern detectors, else T-STR (uncertain) |
| Report inputs (Contract ID, IMEI and similar filters) | report parameter metadata | Report methods are refused in S2 |

If the typing value is missing or unknown, the masker treats the field as an unknown identifier: on a request it refuses; on a response it applies the pattern detectors and, failing a match, a generic T-STR token.

## 6. Masking scheme

### 6.1 Treatments

| Code | Treatment | Reversible by the masker | Used for |
|---|---|---|---|
| T-NUM | Keyed tokenization into a digit surrogate of the same length (a fixed length for number types of unknown format, §6.2), in a reserved prefix, with a valid check digit where the type has one | Yes, through the vault | IMEI, ICCID, IMSI, MSISDN family, capcode, `SUB-`/`SC-` numbers, IMO, MMSI, 19-digit serials, numeric-typed IDs |
| T-STR | Keyed tokenization into a labeled string, `<Label>-<8 base32 chars>`. On an element with a numeric XSD type it becomes T-NUM | Yes | Vessel, organization and group names, `spReference`, customer-entered descriptions, VPN names, other IDs |
| T-IP | Keyed tokenization into a reserved address range | Yes | IPv4, IPv6, subnets |
| T-HOST / T-EMAIL | Keyed tokenization under the reserved domain `example.invalid`; `*` wildcards and ports kept | Yes | Delivery hosts, filter domains, emails |
| P-ONE | One-way pseudonym with the same derivation, no vault row | No | Person names, logins, contact phones, postal address parts, called and calling numbers |
| C | Constant per distinct real value | No | SP account numbers and names, `iwsUsername` |
| G | Generalize | No | Coordinates (1 degree); later, if allowed, vessel build year (decade), tonnage and capacity (bands) |
| D | Drop: on a string element the value is replaced by `REDACTED` and the element kept, so the shape stays; other types follow the XSD rule below | No | Secrets, PINs, PUKs, download URLs, LAC, altitude, vessel quasi-identifiers |
| F | Free text: replaced as a whole by `Text-<8>` (P-ONE derivation, no vault row) unless the value fully matches a reviewed message template, whose typed slots are masked by type (§6.4) | No | Error messages, fault text, reasons, system and catalog descriptions |
| N | Parse the embedded XML or CSV and mask it with the same rules; drop it if it does not parse | — | IWS log and queue payloads, inline report rows |

**Every output must be valid for the element's XSD type** in the field map, so agents' bindings and strict validation keep working. D on a numeric or date element writes `xsi:nil` if the element is nillable; otherwise it removes the element if `minOccurs` is 0; otherwise it writes a type-valid sentinel listed in `overrides.yaml`. T-STR on a numeric type becomes T-NUM. G keeps the type.

Values are kept only where the field map says keep (§6.5): dates, statuses, enums, plan and bundle IDs, catalog names, counts, flags.

### 6.2 Surrogate formats

The reserved prefixes are tentative. Each must occur in **zero** real values of its type in SITEST. Only the masker sees real values, so it checks this itself: when issuing a surrogate, it counts real values that fall inside the type's reserved prefix, refuses to issue for them and writes an incident (count only, never the value). The first recording session (§15.2) reads this counter, and so does every detected SITEST refresh (§8.2). If a prefix does occur, the masker uses the next candidate, and the change is a reviewed constant.

| Type | Real format | Surrogate format | Fake example |
|---|---|---|---|
| IMEI | 15 digits; SBD/M2M+ start with 3 and end with 0 [OW]; no check digit assumed | `99` + 12 derived digits + Luhn digit | `990000000318651` |
| ICCID | 19 digits | `99` + 16 derived digits + Luhn digit | `9900000007582043714` |
| IMSI | 15 digits | `99` + 13 derived digits | `990000000593607` |
| MSISDN | 12 digits starting 8816/8817 [OW] | `99` + 10 derived digits | `990000058306` |
| Other numbers (MSISDN-B/C, PLUS1/PLUS7, local, follow-me, ISDN-A) | Unknown or variable length | Fixed 12 digits, `99` + 10 derived digits, whatever the real length, so the length does not reveal the country | `990000271940` |
| Contract | `SUB-` + 7 digits | `SUB-9` + 6 derived digits (fallback `SUB-X` + 6 digits) | `SUB-9004217` |
| Voucher account | `SC-` prefix; length undocumented (uncertain) | `SC-99` + derived digits, same length | `SC-990815` |
| IPv4 | | `240.0.0.0/4` (reserved, never routable) | `240.18.7.33` |
| IPv6 | | `2001:db8::/32` (documentation range) | `2001:db8::9c1e` |
| Host | | `h-<8>.example.invalid` | `h-k3f9q2m7.example.invalid:4000` |
| Email | | `u-<8>@example.invalid` | `u-k3f9q2m7@example.invalid` |
| Names | | `Name-<8>`, `Vessel-<8>`, `Org-<8>`, `Group-<8>`, `user-<8>` | `Vessel-p2x8c4ra` |
| IMO, MMSI | 7 and 9 digits | `99` + derived digits, same length; IMO check digit recomputed (*Inferred*) | `9900588` |
| SP | | `SP-0001`, `SP-Name-0001` | |

Why these shapes: the same length (where the real length is fixed) and digits keep agent code, XSD types and lengths working; the reserved prefix makes every surrogate **recognizably non-real**. Real values can start with `99` too (for example 12-digit numbers under the assigned E.164 codes 992–996 and 998; general knowledge), so the leak detector exempts only surrogates the masker itself placed in the response, never a value just because of its prefix (§11.1). Domains and address ranges are reserved by standards (`example.invalid`, `240.0.0.0/4`, `2001:db8::/32`; general knowledge, not from the sources). Surrogates that break IWS's own format rules (for example an MSISDN that does not start 8816/8817) are fine: IWS only ever sees real values. Agent tests of format validation use synthetic data, not surrogates.

### 6.3 Derivation, consistency, collisions and check digits

- **Derivation.** `h = HMAC-SHA256(K_mask, TLV(type) || TLV(version) || TLV(real_value) || TLV(counter))`, where each field is length-prefixed, so distinct inputs never concatenate to the same string. The digits or base32 characters of the surrogate body come from `h` (digits: `h` as an integer modulo `10^n`). `type` keeps an IMEI and an IMSI with the same digits apart, and every type is derived independently. `counter` starts at 0.
- **Consistency.** The derivation is deterministic, so the same real value gets the same surrogate in every call, every session and across masker restarts. Consistency is global, not per session. Fixtures do not depend on it: they are re-pseudonymized on export (§9). After a SITEST refresh, values that survive keep their surrogates, but write scope is reset (§8.2).
- **Vault.** Every reversible surrogate issued has a row: `(type, surrogate, counter) → AES-256-GCM(real_value)`, plus first-seen and last-seen times. The vault is the record of what the masker issued (§7). Expired rows become tombstones whose slot is never reused (§9).
- **Collisions.** On issue, the masker looks up `(type, surrogate)`. If the row (or a tombstone) holds a different value, it increments `counter` and derives again. Collisions are expected, not rare. Surrogate space per type (*Inferred*): `SUB-` 10^6 (about 500 expected collisions at the assumed ~32,000 contracts, Annex D §2.4); IMO 10^4; `SC-` 10^(digits − 2); MMSI 10^7; MSISDN and other numbers 10^10; IMEI 10^12; IMSI 10^13; ICCID 10^16. The masker refuses to issue past 50% occupancy of a type's space (tombstones count) and raises an alarm (*Inferred* threshold); for IMO and short `SC-` numbers that cap is reachable, and the CTO then approves a longer or second prefix.
- **Check digits.** Recomputed for the surrogate (Luhn for IMEI and ICCID). The real value's check digit is never copied.
- **Key.** `K_mask` is a 256-bit key generated once, stored only wrapped by a KMS key (§13.2). It is never rotated in normal operation, because rotation changes every surrogate. KMS rotation of the wrapping key is transparent. Keeping `K_mask` inside KMS as an HMAC key, and adding surrogate epochs, are open (§17 #20).

### 6.4 Free text, embedded payloads and faults

- **Known-value replacement.** For each call, the masker keeps the set of real values it replaced in structured fields, the real values it put into the request (§7), and the auth values it injected (`iwsUsername`, `serviceProviderAccountNumber`, `signature`, the signed timestamp). It then replaces any occurrence of those strings in free text, fault text and embedded payloads with the matching surrogate, constant or `REDACTED`. This catches IWS error messages that echo the request value.
- **Cross-call known values.** The masker keeps a keyed-hash set (HMAC with its own KMS-wrapped key, no plain values; stored and expired with the vault) of every real T-STR, P-ONE and T-EMAIL value of 4 or more characters ever seen in a structured field. Word sequences (1–4 words) in output strings are checked against it: a hit is tokenized in F fields and blocks the response in kept fields. This is the backstop for names, which match no pattern.
- **Free text (F).** A value is kept only if it fully matches a reviewed message template, for example an IWS error message with a typed slot for an account number. Templates are added by the CTO from recorded masked samples, never copied from the catalog. Template slots are masked by their type. Anything else is replaced as a whole by `Text-<8>`. `otherInfo`, tracker and email bodies, and `reason` are always tokenized.
- **Pattern detectors** (§11.1) then run over every template slot and every kept string. A match is tokenized by its detected type.
- **`spReference` and customer-entered descriptions** (account metadata, subscriber organization, vessel, resource group, tracker, pooling group, voucher order, PTT device) are tokenized as whole values (T-STR, reversible), because they may hold customer names or order numbers. Catalog and system descriptions (outages, call types, IMEI profiles, notifications) get F, so templates can keep the ones agents need.
- **Embedded XML** (`iwsLogImpl.request`/`response`, `baseQueueEntryImpl.request`/`response`) is unescaped, parsed with the same safe parser, masked with the field map of the operation it names, and re-escaped. It is masked only if its root element equals `requestedOperation` (or `operation`) and that operation is allowlisted; otherwise, or if it does not parse, the element is dropped (D). Auth fields inside it (`signature`, `callerPassword`) are dropped first.
- **CSV rows** (`reportResultDetailsEntryImpl.row`) need the report's column map (§17 #6). Until then the method is refused.

### 6.5 Unknown elements: fail closed

Every element and attribute path in every allowed method's request and response, keyed by (operation, `xsi:type`, path), is classified in a field map: one of the treatments above, or "keep". The generator reads the live WSDL (§12.2) and emits every path as **UNCLASSIFIED**. Only the reviewed override file assigns a treatment, `keep` included. The generator may propose `keep` for booleans, enumerations, dates and numeric quantities; each proposal is listed in the generated file for review and takes effect only once copied into the override file. It never proposes `keep` for `xsd:string` or ID-like integers: the CTO classifies those one by one (for example catalog names and plan IDs). CI fails on any UNCLASSIFIED path in an allowed method.

At runtime, an unknown path, an unknown `xsi:type`, any attribute other than `xsi:type` and `xsi:nil`, or non-whitespace text outside a leaf element blocks the whole response (§11.4) until the CTO classifies it; the metric raises an alarm. `X-Masker-Dropped` counts the elements the policy removes on purpose. Strict mode is a code constant: there is no non-strict mode in S2. This mirrors the gateway rule that CI fails on an unclassified WSDL operation (Annex D §2.1).

### 6.6 Recommendation: keyed tokenization with a vault, not FF1

| | Keyed tokenization + vault (recommended) | NIST FF1 format-preserving encryption, KMS-protected key |
|---|---|---|
| Consistency | Deterministic derivation | Deterministic |
| Reverse mapping | Vault lookup | Decryption, no storage |
| Scope limit (§7) | Natural: only issued surrogates have a vault row, so a guessed surrogate maps to nothing | None: every string in the format decrypts to some real value, so an agent could enumerate surrogates and act on arbitrary real lines; scope needs a separate allowlist anyway |
| Recognizably non-real | Yes: room for a reserved prefix, because the vault, not the format, carries the information | Hard: a reversible mapping of n-digit strings onto n digits leaves no room for a reserved prefix plus a valid check digit |
| Leak detection | At runtime: any real-format value the masker did not place in this response. Offline (fixture scans, people reading output): anything outside the reserved prefixes | Offline scans and readers cannot tell a surrogate from a real value by format |
| Storage and state | A vault table (rows grow with the identifiers seen) | None |
| Library risk | HMAC and AES-GCM from the standard library and `cryptography` | Few maintained, audited Python FF1 implementations (*Inferred*; would need its own review) |

The vault costs a table and one lookup per identifier. Recognizable surrogates and the scope limit are worth that.

## 7. Requests that carry masked identifiers

1. The masker validates the request against the WSDL schema, then classifies every element with the field map (§6.5). Any element beyond its `maxOccurs`, mixed content, a comment, processing instruction, CDATA section or DTD, an unknown attribute, or an `xsi:type` outside the field map refuses the request with `422`. An unknown element refuses it too. This closes parser differentials: the masker reads the first of two duplicate elements, while a Java binding on the IWS side may keep the last.
2. For each identifier field, the value must be a surrogate **the masker issued**: a vault row for `(type, surrogate)` must exist. The type comes from the field map or the typing enum (§5.2). If no row exists, or the surrogate is outside the token's read scope (§4.2), the request is refused with `IDENTIFIER_NOT_ISSUED`, by the same code path. A real-format value outside the reserved prefixes is refused with `422`, because no agent should hold one.
3. The masker replaces each surrogate with the decrypted real value in memory and records the pair for known-value replacement on the way back (§6.4).
4. Free-text fields in the request are scanned by the detectors. A match refuses the request: this stops an agent from writing a real identifier into SITEST, from where it could come back unmasked in another field.
5. **Reads.** Surrogates are global handles: any issued surrogate can be used for reads within the token's read scope. Fixtures carry re-pseudonymized values that resolve to nothing (§9). Guessing works rarely (about 3% of guessed `SUB-` surrogates hit an issued row at 32,000 issued, *Inferred*), so guesses alarm (§11.5 #6) and daily budgets cap what any token can pull (§10).
6. **Writes** may use only surrogates that are both issued **and** in the plan's scope: the plan's signed test inventory, or accounts derived from it (§8.2).
7. Literal values a write needs must be real, non-personal values Globalsat controls (for example `spReference` `GS:TEST-001`) and must be listed in the plan's `allowed_literals`. The CTO's test mailbox is registered inventory of type EMAIL, not a literal. Anything else that looks like an identifier is refused.
8. **Search inputs.** Every search input aimed at a masked field is identifier-typed and must be an exact issued surrogate; free text is never accepted in a search input, so partial-match searches cannot be used to rebuild a real name character by character. Surrogates in wildcards (`*`, `%`) cannot be mapped, so wildcards on identifier filters are refused. `accountSearch.filterCond` must be `EQUALS` (absent means `EQUALS`): `CONTAINS`, `LIKE`, `NOT_EQUAL` and the other negations are refused. `getVessels` accepts only `id`, `imo`, `mmsi` or a full issued `Vessel-` surrogate. `getSubscriberOrganizations` accepts only an issued `Id`. `getQueueEntries.createdBy` is overwritten with the masker's own value for the session (its `caller` or the IWS username, whichever IWS records; uncertain until the recording session), so no agent types a real login.

## 8. Write guard (S2b)

### 8.1 Test plan format

A plan is a YAML file in this repository under `test-plans/` [path open], reviewed in a PR like code, then loaded into the masker by the CTO with `masker-admin plan load`, which signs it. The CTO reviews raw YAML but signs what the loader parses, so the two must not differ:

- Plans are parsed with a strict loader: no duplicate keys, anchors, aliases, merge keys or tags; schema-validated; unknown keys refused.
- `plan load` reads the merged file from `main` by commit SHA, checks the blob hash, prints the canonical parsed plan (with each inventory entry's service and the last 4 digits of its real value, to compare with Iridium's assignment list), and signs only after the CTO types the plan id. The commit SHA and the KMS approval are recorded in the masker database; neither is committed, because a file cannot contain the SHA of the commit that merges it.

```yaml
id: TP-2026-001
title: SBD activation, suspend and resume on assigned test inventory
purpose: Annex F ST-04, checklist v1.7 "Account Activation - SBD"
valid_from: 2026-11-23T00:00:00Z
expires_at: 2026-11-30T00:00:00Z          # at most 14 days after valid_from
max_writes: 20                            # budget for the whole plan
allowed_methods:
  - method: activateSubscriber
    service_types: [SBD]
  - method: setSubscriberAccountStatus
    new_status: [SUSPENDED, ACTIVE]      # DEACTIVE and CLOSED are hard-blocked anyway
  - method: accountUpdate
    status_change: forbidden
    mutable_fields: [subscriberAccountMetadata.spReference]   # every other difference is refused (§8.2 step 6)
allowed_inventory:                        # surrogates of signed test-inventory rows only
  - {type: IMEI, surrogate: "990000000725905", service: SBD}
  - {type: IMEI, surrogate: "990000000182073", service: SBD}
  - {type: EMAIL, surrogate: "u-q7m2x9k4@example.invalid", service: SBD}   # the CTO's test mailbox, registered inventory
allowed_literals:                         # real, non-personal values Globalsat controls
  - {field: subscriberAccountMetadata.spReference, value: "GS:TEST-001"}
dry_run_required: true                    # each request hash must be dry-run before it is sent
# The commit SHA and the KMS approval are recorded by plan load in the masker database, never in this file.
```

**Test inventory registration.** Iridium's assigned test inventory (re-plan §11.1 Q10) is registered by the CTO with `masker-admin inventory add` through the admin path (§14.3, §17 #16), with MFA. The CTO types each value interactively, never as a command-line argument or task override, which shell history or CloudTrail could keep. The tool writes the real value to the vault and a row to a separate **test-inventory table**, and prints only the surrogate for the plan. Only the CTO's database role can write that table; the masker role has `SELECT` only. Each row is signed with the plan-approval key (the CTO's approval role) over (type, surrogate, HMAC of the real value, service). `plan load` refuses any `allowed_inventory` entry that is not a signed inventory row. IAM and database grants are the control, not the CLI's own identity check (§12.2). Real inventory values never enter git, a plan file or an agent session.

### 8.2 Enforcement, in order

1. Token scope includes `write:<plan-id>` and matches `X-Test-Plan`.
2. The plan exists, its KMS signature verifies against the plan-approval key, the current time is inside its validity, it is not revoked, and its write budget is not spent. Agents cannot sign plans: only the CTO's role has `kms:Sign` on that key.
3. The method is in the global write allowlist (§4.2) **and** in the plan, with its constraints (service type, allowed status values).
4. The hard blocks pass (§8.5).
5. Every identifier is issued **and** in scope (§7): a signed test-inventory row named in `allowed_inventory` (the signature is re-verified on every write), or a derived account of this plan. Derived accounts come only from the success field of an `activateSubscriber` response, after a read confirms that the account's device is the plan's signed test-inventory device. Writes address accounts by contract number only (`updateType` `SUBSCRIBER_ACCOUNT_NUMBER`, or `accountNo`). Before every write, the masker re-reads the target and refuses unless its devices are signed test inventory, because SITEST is refreshed from production and a number in scope yesterday can belong to a real contract today. Derived sets expire with the plan and are cleared on a detected SITEST refresh (a `getProjectVersion` or `getSystemStatus` version change, or a CTO flag); writes then stay off until the CTO re-enables them.
6. `accountUpdate`: the masker reads the current account (`getSubscriberAccount`, required before `accountUpdate` anyway; Annex D D4) and diffs the agent's object against that read. Fields with non-reversible treatments (P-ONE, C, G, D, F) must equal the masked value from the read and are restored to the real values from the read. Each changed field must be listed in the plan's `mutable_fields` for that method; any other difference is refused. `accountStatus` always comes from the read, and `sim`, `imei`, `msisdn` and `ip` may not change in S2b (§4.3).
7. If the plan requires it, a dry run with the same request hash was made in this plan within the last 24 h.
8. Idempotency (§8.4), then the permit, then the send. No automatic retry on a write (Annex D §2.5).

### 8.3 Dry run

`X-Dry-Run: true` runs steps 1–7 and the unmasking, builds the final request without signing it, and returns the **masked** final request plus the verdict, without contacting IWS. The record stores the request hash, so step 7 can match it. A dry run never spends write budget.

**Request hash** = HMAC-SHA256(`K_req`, canonical masked request). The canonical form is the agent's surrogate-bearing request after schema validation, without headers or timestamps, so a dry run and its send match. `K_req` is a separate data key wrapped by the masker KMS key. The hash is never returned to agents and is not part of `/v1/calls`. Nothing anywhere hashes unmasked bytes: a plain hash of a low-entropy real identifier could be reversed by brute force.

### 8.4 Idempotency

`X-Idempotency-Key` is required on writes. The masker stores `(plan, key) → request hash, call id, outcome, masked response`. The same key with the same hash returns the stored masked response without resending. The same key with a different hash is refused with `409`. A timeout or an IWS system error on a write is recorded as `unknown`, never retried; the agent resolves it with the probes in Annex D §2.5 (for example `accountSearch` after an activation), all of which are reads.

### 8.5 The hard block on DEACTIVE

The block is code, not plan data, so no plan can lift it:

- `setSubscriberAccountStatus` with `newStatus` `DEACTIVE` or `CLOSED`, or with `bypassQuarantine` present with any value other than `FALSE`, is refused with `ALWAYS_REFUSED_DEACTIVE` before any other check. The comparison runs after NFKC normalization, trimming and case folding, so ` DEACTIVE `, `Deactive` or full-width text are caught.
- `accountUpdate` that would change `accountStatus` is refused (step 6).
- `activateSubscriber` with `bulkAction` other than `FALSE` or absent, any `*BulkDetails` element, or a `BULK` literal in a device field is refused with `ALWAYS_REFUSED_BULK`.
- Every method in the always-refused list (§4.3) is refused, including bulk and destructive ones.
- The outgoing envelope is **rebuilt from scratch**, never edited from the agent's tree: no SOAP Header, exactly one Body child, enum values such as `newStatus` written from the masker's own constants (`SUSPENDED`, `ACTIVE`), never the agent's bytes; Content-Type and action set by the transport; no agent header forwarded. The check then runs again on the final bytes after unmasking and auth injection.
- The hard block applies to every token, the CTO's included.
- Any attempt raises an alarm (§14.4). It is never silent.
- The block and its tests live in files on the mandatory review list (`masker/policy/hard_blocks.py`, `tests/masker/test_mask_hard_blocks.py`).

DEACTIVE in the spike's SBD lifecycle and in the final dry run stays a CTO action outside the masker (re-plan §3.2; S5). Recommended CTO path (§17 #7): a manual call from the CTO's trusted machine, with the masker paused so that no agent request competes for the two permits, recorded afterwards with `masker-admin note` so the call log and the evidence index show it. Each DEACTIVE of an SBD line releases its IMEI (Annex E §1.4), which frees test inventory for the next ST-04 run.

## 9. Recorder and call log

**What is stored, masked only.** No unmasked request or response is ever written to disk, a log or S3.

| Record | Fields | Where |
|---|---|---|
| Call log row (append-only: the masker's database role has no `UPDATE` or `DELETE` on this table) | `call_id` (UUIDv4), UTC start and end, token `jti` and `sub`, source IP, plan id, operation, endpoint, class (read or write), dry run, decision and refusal code, permit wait, IWS duration, outcome (`ok`, IWS fault code from `errorCodeEnum`, `unknown`), the `caller` value sent to IWS, the signed UTC timestamp sent, IWS request id if returned, idempotency key, request hash (keyed, §8.3), counts of dropped elements and detector hits | RDS Postgres, schema `masker` |
| Masked exchange | Masked request and masked response XML, compressed. For refused requests, every detector hit in the stored body is replaced by `<detector-id>`, and the detectors run again before `PutObject` | S3 bucket `…-masker-recordings`, KMS, versioning, block public access, TLS-only; the masker role can only `PutObject` |
| Incident row (runtime detector) | `call_id`, element path, detector id; never the value | RDS |
| Vault | §6.3, plus the cross-call known-value hash set (§6.4) | RDS, schema `masker_vault`, separate role, values encrypted with a KMS-wrapped key |
| Test inventory | Signed rows (§8.1) | RDS, schema `masker_inventory`; the CTO's role writes, the masker role reads |

**Application logging.** Logs are structured and carry an allowlisted field set only: call id, codes, timings, counts. A logging filter runs the §11.1 detectors and the known-value sets on every record; on a hit it drops the record and raises the leak alarm. Exceptions on the IWS path are logged as type and code only, with no message and no local variables, because lxml, aiohttp and validation errors can echo input. There is no debug mode. Validation errors return codes, not inputs. Metric dimensions never carry values. A leak test drives every error path with canary data and asserts that the logs stay clean (§11.2).

**Retention (recommended; Legal sets the final periods per country, re-plan §5 item 5).** Call log: 18 months, like the gateway's technical log (Annex D §2.8). Masked exchanges: 90 days, except samples promoted to fixtures. Vault rows: after 90 days unused, the encrypted value is deleted, but `(type, surrogate, counter)` stays reserved forever as a tombstone: a reserved slot is never issued to another value, so an old surrogate in a session or plan can never come to mean a different person. Test-inventory rows and rows referenced by a loaded plan never expire. Masked data is still pseudonymized personal data while the vault exists. Deterministic derivation means the next sighting of a value recreates its old surrogate, so deleting rows does not unlink anything (epochs are §17 #20). Agent transcripts are also pseudonymized personal data, held by the agent provider outside Globalsat's retention; Legal confirms the basis.

**Fixtures.** The CTO promotes chosen masked exchanges to `tests/fixtures/masked/` with `masker-admin export`. Export re-pseudonymizes them with a separate one-way fixture key (no vault rows, consistent within the fixture set), so fixture values never resolve live, then re-runs every detector and the fixture scan (§11.3). They reach git only through a PR the CTO reviews; the path matches `**/*mask*` in CODEOWNERS. They feed the IWS simulator and contract tests (Annex E §5; re-plan §3.1).

**How the evidence module tells agent runs from certification runs** (re-plan §3.4; Annex E §2.3):

1. Separate logs. The evidence module (S4) reads only the gateway's exchange log in certification mode, never the masker's call log.
2. `caller` marking in Iridium's own log. The masker always sets `caller` to `agent.<short-jti>`; certification runs use the gateway's `gs.<tenant>.<user>` form (Annex D §2.8). `getIwsRequests` returns `caller`, so an extract can be split by prefix. The User Activity Report aggregates by IWS user and month and has no caller column (catalog `reports_library.md`), so it cannot separate agent calls; Annex D §2.8 says otherwise, so this is uncertain until verified on SITEST.
3. Quiet windows. Agent access is paused automatically for the two S5 dry runs and the certification run (a flag the CTO sets with a start and end time). The evidence module checks that the `getIwsRequests` extract for the window holds no `agent.` caller, or it marks the run void. Until a second SITEST IWS user exists, the User Activity Report for the month still counts agent calls: either pause agents for the whole calendar month of each certification-mode run, or state in the evidence index that agent traffic shares the user.
4. Stronger, if Iridium agrees: a second SITEST IWS user for agent traffic, so `iwsUsername` itself differs (open decision §17 #5; Annex D §2.4 already proposes `gs-cert` and `gs-ci`).

## 10. IWS concurrency

- **The limit.** 2 concurrent requests per IWS user; the third gets "Too many connections!" (catalog Rules). Annex D assumes the limit is shared between the provisioning and reporting endpoints until Iridium confirms otherwise (Annex D §2.4).
- **Same permit system as the gateway.** S2 builds the gateway's permit module (§12) as a Postgres ledger, and the masker uses it through `gateway.sitest_port`. One row per `(IWS user, slot 1..2)` with holder, lease expiry, fencing epoch and a cooldown time. Row-level security limits the masker's database role to the SITEST user's rows. Acquire is a conditional update; release clears the holder; a call cut off by timeout puts the slot in cooldown for 30–60 s, because IWS may still be working on it (Annex D §2.4, inferred there).
- **The masker's share.** The masker may only take **slot 2 (permit B)**, never slot 1 (permit A, reserved for interactive L0–L2 traffic; Annex D §2.4). So at most 1 agent request is ever in flight, and one slot is always free for the CTO or, from S3, the gateway. The masker's HTTP connector to SITEST is also limited to 1 connection, so the transport cannot exceed its share even if the ledger is wrong.
- **Physical cap across processes.** Annex D's guarantee is physical: one process holds a pool of 2 connections (Annex D §2.4). From S3 the gateway prototype (connector limit 2; Annex F §6.1) shares the SITEST user with the masker. While the masker is enabled on that shared user, the gateway's SITEST connector limit is 1 (permit A only), so the physical cap stays at 2 across both processes; a test asserts it. Masker deploys use `minimumHealthyPercent` 0 and `maximumPercent` 100 plus a startup advisory lock (the D2 pattern), so a deploy never runs two masker processes (re-plan §9 risk register).
- **Before the gateway runs.** In S2 the masker is the only automated SITEST client. The CTO's manual calls (SoapUI or the WSDL Explorer) do not use the ledger, so the CTO makes them one at a time, or pauses the masker first.
- **Per-session limits (*Inferred* defaults, configurable by the CTO):** 1 request in flight per token; 20 calls per minute; 1,000 calls per day; 20 writes per plan unless the plan sets fewer. A request that would wait more than 10 s for the permit fails fast with `IWS_BUSY`, `503` and `Retry-After` (Annex D §2.4 backpressure). Long-class methods (`getSpBalance`, raw usage, reports) are not in the S2 allowlist.
- **Daily budgets of distinct records (*Inferred*).** Calls per day alone would let a token copy the masked base (1,000 calls × 50 rows). So the masker also caps the distinct subscriber records issued: 500 per token per day (lower for `read:sp`, §17 #19) and 2,000 per day overall. A vault-growth alarm fires above the daily norm.
- **"Too many connections!"** is an alarm: it means someone else is using the credential or the ledger leaked (Annex D §2.5). Reads get one retry after a backoff; writes never.

## 11. Leak tests and runtime fail-closed

### 11.1 Detectors

| Detector | Rule | Source |
|---|---|---|
| IMEI | Any 15-digit run that is not a placed surrogate; Luhn not required (a valid Luhn digit only raises confidence) | [OW]: SBD/M2M+ IMEIs end in 0, and catalog examples fail Luhn |
| ICCID | 18–20 digits starting `89` with a valid Luhn digit, or any 19 digits, not a placed surrogate | [OW] 19 digits; `89` prefix and Luhn *Inferred* |
| IMSI | Any 15-digit run that is not a placed surrogate (overlaps IMEI; either hit blocks) | [OW] |
| MSISDN | 12 digits starting `8816` or `8817`; also `+` or `00` followed by those | [OW] |
| Phone numbers in text | E.164-like `+` and 8–15 digits | *Inferred* |
| Contract | `SUB-` + 7 digits or `SC-` + digits, not a placed surrogate | [MP], [OW] |
| Voucher serial | 19 digits, not a placed surrogate | [OW] |
| IPv4 / IPv6 | Any address that is not a placed surrogate (offline: any address outside `240.0.0.0/4` and `2001:db8::/32`) | — |
| Email | Any address that is not a placed surrogate (offline: not ending `@example.invalid`) | — |
| IMO / MMSI | 7-digit IMO with valid check digit; 9-digit MMSI | *Inferred* |
| Long digit runs | 9 or more consecutive digits in every string element, except placed surrogates and the operational fields of §11.4 | catch-all |
| Known values | Exact match of any real value seen in this call, including the injected auth values (§6.4) | — |
| Cross-call known values | Keyed-hash match of output word sequences against every real name-like value seen (§6.4) | — |
| Signatures | Any Base64 string of HMAC-SHA1 length (27–28 characters, `=` padding) anywhere in output | Catalog signature algorithm; length rule *Inferred* |
| Sensitive names | Elements named like the secrets in §5.1 with a non-`REDACTED` value | Annex D §2.8 |

**Exemption.** A value is exempt only if it is byte-equal to a surrogate the masker placed in this response (a per-response set). A value that merely looks like a surrogate, but that the masker did not place, is a hit. Offline scans, which have no such set, use the reserved prefixes (§11.3).

Detectors also run after Unicode normalization (NFKC) and base64 decoding of long base64-looking strings. Separator removal is limited to digit groups joined only by spaces, hyphens or dots that total 12–20 digits, and it skips ISO-8601 and `DD-MON-YYYY HH24:MI:SS` timestamps. So `9 9 0…`, full-width digits or encoded copies do not slip past, while timestamps and version strings do not trip a rule. Detectors use linear-time regular expressions (RE2 or bounded patterns), so no input can make them backtrack for long.

### 11.2 Per-response-shape tests from synthetic data

- For every allowed method, a test builds a synthetic response from the WSDL schema (every optional element present, arrays of 1 and 3, each account subtype by `xsi:type`, nil and empty variants) and fills every identifier field with **canary** values: real-format values from a documented canary range that is not a surrogate prefix, so the detectors fire on them. The test asserts that the masked output contains no canary, no detector hit, every secret `REDACTED` (or nil or absent, §6.1), the same element structure, and that it validates against the WSDL schema.
- A **log leak test** drives every error path with canary data and asserts that no canary reaches the application logs (§9).
- The same for requests: every allowed write with surrogates maps back to the canaries, and every refused case is refused.
- A **deny-list test** on every response shape: the list of secret element names and the real-format patterns must never appear in output.
- Property-based tests (Hypothesis) for the detectors, tokenization round trips, collision handling and check digits.
- File names contain `mask` or `leak` (`tests/masker/test_mask_*.py`, `tests/leak/test_leak_*.py`), so CODEOWNERS routes them to the CTO.

### 11.3 Fixture scanning before git

- `scripts/leak_scan.py` runs every detector of §11.1 over all text files in the repository, with fixtures under `tests/fixtures/` in strict mode. It allows reserved-prefix surrogates, and the canary range only under `tests/leak/` and `tests/masker/`; the masker's in-prefix counter (§6.2) also confirms that the canary range is absent from SITEST. In CI it scans every commit in the PR range, not just the working tree, so a value added and removed inside a PR is still caught. It refuses non-UTF-8, binary or compressed files under `tests/fixtures/`. It runs in `make security` (and so in CI) and in the pre-commit hook.
- gitleaks keeps scanning for secrets (`make security`, CI history scan), with a rule for the masker token prefix `gsm_` (§3.3); the same pattern is registered with GitHub secret scanning. Its regex rules cannot check Luhn digits, so identifier detection lives in `leak_scan.py`.
- Adding the script and the Makefile target changes gate configuration, which is on the mandatory review list.

### 11.4 Runtime detector: block and alarm

After masking and before responding, the masker runs the detectors over the masked response, including decoded embedded payloads. Detection is field-aware. Type detectors run on every element whose field-map class is an identifier treatment, F, N or unknown, and on every kept string element. Kept elements with an XSD numeric, date or boolean type, and kept elements listed in `overrides.yaml` as a version, size, count or operational ID (for example `iwsVersion`, `wsdlRevision`, project version fields, `cdrId`, `sessionId`, `requestId`, `transactionId`, `bulkRequestId`, `queueEntryId`), skip the IPv4, MMSI, IMSI and long-run rules; they are still checked against known values. Otherwise a version such as `22.2.0.1` (Annex E §1.4) would trip the IPv4 rule and disable `getSystemStatus`.

**Fail closed on every failure, not just on hits.** Bytes are returned only when every stage returns an explicit clean result. Any exception, a masking-budget timeout (2 s, *Inferred*), an unavailable vault, KMS or database, a failed revocation or pause-flag read, a non-SOAP body (such as an HTML error page), a response over 5 MB (*Inferred*), or a list with more rows than the request allowed gives `502 MASKING_BLOCKED` or `503`, never IWS bytes.

On any hit, or on an unknown element:

1. The response is **not** returned. The agent gets `502` with `MASKING_BLOCKED` and the call id.
2. An incident row is written with the element path and detector id, never the value.
3. A CloudWatch metric raises an SNS alarm to the CTO at once.
4. The method is disabled for all agents until the CTO re-enables it. Three blocks within an hour pause all agent access (*Inferred* thresholds).

Nothing raw is kept for debugging. No token scope or mode disables masking, the CTO's tokens included. If the CTO needs the raw response, the reproduction happens only on the CTO's trusted machine, outside the masker; the fix is then verified through the masker.

### 11.5 Red-team cases (part of the S2 test suite)

1. IWS error text that echoes a request value (`accountSearch` with a wrong filter type; `setSubscriberAccountStatus` on a missing account).
2. Escaped XML in `getIwsRequests` and `getQueueEntry` that contains other callers' requests, including `signature` and `callerPassword`.
3. Every account subtype through `getSubscriberAccount`, with identifiers in subtype-only fields (Certus voice lines, OpenPort phone lines, Paging `isdna`, vessel links).
4. Identifier variants: leading zeros, spaces, hyphens, `+` and `00` prefixes, IMEISV (16 digits), 14-digit IMEI without check digit, an SBD IMEI ending in 0 with an invalid Luhn digit, 20-digit ICCID, a real 12-digit number starting `99`, IPv6, mixed-case emails, full-width digits, values split across elements.
5. Free text and names containing identifiers and prompt-injection text; a name seen in a structured field in an earlier call, echoed in free text.
6. Enumeration: an agent sends guessed surrogates in the reserved prefix. Most guesses fail with `IDENTIFIER_NOT_ISSUED`, and issued surrogates outside the token's read scope get the same answer; the `IDENTIFIER_NOT_ISSUED` rate alarms above a threshold (*Inferred*); rate limits and daily budgets hold.
7. An agent tries to write a real-format identifier into `spReference` or `description`.
8. Operation-name and parser tricks: wrong case, a root element that differs from the path, a Content-Type `action` mismatch, two operations in one body, auth fields in the request, a `caller` set by the agent, duplicate `newStatus` or `accountNo` elements, a comment-split enum (`DE<!---->ACTIVE`), ` DEACTIVE `, `Deactive`, full-width text, `wsa:ReplyTo` and other SOAP headers, `xsi:type` substitution.
9. Endpoint tricks: Beta or production host names in headers, URLs or XML; redirects from the IWS side (never followed).
10. XML attacks: external entities, entity expansion, huge documents, deep nesting (parser with entity resolution and network access off and size and depth limits).
11. DEACTIVE through every path: `newStatus` DEACTIVE or CLOSED, `accountStatus` in `accountUpdate`, `bypassQuarantine` with any value but `FALSE` (`FALSE` is accepted), a plan that lists DEACTIVE (must fail to load), bulk methods, `activateSubscriber` with `bulkAction` `TRUE`, a `*BulkDetails` element or a `BULK` device value, the same requests under a CTO token.
12. Token tricks: expired, wrong key, `none` algorithm, an `HS256` token, a `jku`/`x5u`/`jwk` header, read scope used for a write, a revoked `jti`, a plan id in the header that differs from the token.
13. Concurrency: 5 parallel agent requests never put more than 1 in flight to SITEST; a gateway-held slot is never taken.
14. `background=TRUE` on `createOnDemandReport` and every other always-refused method.
15. No false blocks: `getSystemStatus` and `getProjectVersion` with versions such as `22.2.0.1`, a kept 9-digit count, and a `statusDescription` holding a space-separated timestamp are not blocked.
16. Search oracles: prefix walking on `getVessels.vesselName`, `NOT_EQUAL` and `CONTAINS` on `accountSearch`, a name search on `getSubscriberOrganizations`, login guessing on `getQueueEntries.createdBy`: all refused or overwritten.
17. Egress from the task: `1.1.1.1:443` (DNS over HTTPS), an `execute-api` host, a `lambda-url` host and a foreign S3 bucket all fail.
18. Fail closed: an exception inside masking, a masking timeout, the vault or KMS unavailable, a failed revocation read, an HTML error page from IWS, an oversized response, and a list with more rows than requested all return `502` or `503` and no IWS bytes.
19. Bulk pulls: `numResults` 0, `limit` 0, a blank `getSubscriberOrganizations` `Id`, `startRow` beyond the cap, an unfiltered `accountSearch` without `read:sp`: all refused; the daily distinct-record budgets hold.
20. A signature-length Base64 string in fault text, and an `iwsLogImpl` entry from another caller, never reach the agent.
21. Write scope after a simulated SITEST refresh: a derived account whose device is no longer test inventory is refused; an `accountUpdate` that changes a field not in `mutable_fields`, or writes `REDACTED` back, is refused.

## 12. Code layout and module boundaries

### 12.1 How the masker calls SITEST before the gateway exists

| Option | What it means | For | Against |
|---|---|---|---|
| 1. Minimal signer inside the masker | The masker has its own HMAC signer, envelope injection and HTTP client | Fastest start; no gateway work in S2 | Two signers and two IWS clients for the CTO to review and keep in step; breaks "gateway is the only code that talks to IWS" (`CLAUDE.md`), which would need a `CLAUDE.md` change; S3 rebuilds the same code |
| **2. S2 builds the gateway's signer core; the masker uses it through `gateway.sitest_port`** (recommended) | S2 writes the first gateway modules: signing, auth injection, the SITEST endpoint, an HTTP transport with a connection limit, and the permit ledger. `gateway.sitest_port` exposes a narrow SITEST port, separate from the console's `gateway.api` | One signer, reviewed once; the "only the gateway talks to IWS" rule stays true; S3 starts with signing done and ST-02's offline vectors already written (re-plan §10 puts them in week 5) | S2 grows by the signer work (§16); the masker depends on gateway code, so a contract change is needed |
| 3. The CTO makes the first live calls | No code; the CTO uses SoapUI or the WSDL Explorer | Useful for `authenticatedPing` and WSDL harvest now | Does not let agents work; raw responses would land on the CTO's machine. Kept only as the first live step (§15.2) |

**Recommendation: option 2.** The signer core is small (UTC timestamp, HMAC-SHA1 over operation name plus timestamp, Base64; Phase 1 plan §1.3; Annex D §2.3) and S3 needs it anyway. D1 is not closed yet. If fallback A replaces the gateway with a plain-Java service (Annex F §6.3), the masker either keeps the Python signer core as its own SITEST client (a second signer, which needs a `CLAUDE.md` change) or calls the gateway service over the Annex D §2.1 interface; decided at G1.

**Residual risk of option 2 in one process.** A compromised masker process holds the SITEST secret, which also works on Beta, and can return it in a response to an agent; no network control blocks that channel. Isolating the signer so that the masker process never holds the secret is open decision §17 #17.

### 12.2 Package plan

```text
src/airtimesat_platform/
  gateway/                      # S2 builds the core; S3 grows it
    api.py                      # the console's public port (unchanged)
    sitest_port.py              # the masker's only entry point: SitestPort protocol + factory sitest_port(secrets, ledger)
    signing.py                  # HMAC-SHA1 signature, UTC timestamp, operation from root element
    envelope.py                 # rebuild the outgoing envelope; auth fields and caller as first children of <request>
    endpoints_sitest.py         # the two SITEST URLs as constants; nothing else
    transport.py                # aiohttp client, connector limit, no redirects, host pinned to the endpoint
    permits.py                  # Postgres permit ledger (slots, leases, cooldown, epochs)
    wsdl/                       # WSDL snapshot (moved forward from S3; open decision §17 #10)
      fieldmap/                 # generated paths, all UNCLASSIFIED, plus keep proposals (§6.5)
  masker/
    __main__.py                 # startup self-tests (§13.3), then the web app
    app.py                      # FastAPI routes: /healthz, /iws/sitest/..., /v1/session, /v1/methods, /v1/calls/{id}
    auth.py                     # token verification, scopes, revocation
    service.py                  # pipeline: auth → validate → policy → unmask → permit → send → mask → detect → record
    logsafe.py                  # allowlisted structured logging and the detector filter (§9)
    policy/
      allowlist.py              # read and write allowlists with limits
      hard_blocks.py            # DEACTIVE, bulk and always-refused list
      plans.py                  # plan model, strict loader, signature check, scope, budgets, idempotency
      rate_limits.py            # rate limits and daily budgets
    fieldmap/
      overrides.yaml            # reviewed classifications: the only place a treatment is assigned
    tokenize/
      surrogates.py             # derivation, prefixes, check digits
      vault.py                  # issue, resolve, collisions
      keys.py                   # KMS unwrap of K_mask and the vault key
    xmlsafe.py                  # lxml parser settings, embedded XML, serialization
    detect/
      patterns.py               # §11.1
      scan.py                   # runtime detector, known values
    recorder.py                 # call log and S3 writes
    admin/                      # CTO-only CLI: keys init, mint, plan load, inventory add, export, pause, note
tests/
  masker/test_mask_*.py         # unit, shape and red-team tests
  leak/test_leak_*.py           # deny-list, log and fixture-scan tests
  gateway/test_signing.py       # offline signature vectors (ST-02)
  fixtures/masked/              # promoted, reviewed, re-pseudonymized recordings
scripts/leak_scan.py
```

The generated field map sits under `gateway/wsdl/`, because `CLAUDE.md` keeps WSDL-derived files under `gateway/`; the masker reads it through `gateway.sitest_port`. The admin CLI ships in the same package but needs AWS and database permissions only the CTO's admin roles have (`kms:Sign`, inventory writes, §14.3). It refuses to run unless its caller identity is the CTO's role, but that check is a convenience: the IAM and database grants are the control.

### 12.3 Import-linter and rule changes

| Change | Why |
|---|---|
| `masker-isolated`: keep `gateway` forbidden, with `ignore_imports` = `airtimesat_platform.masker -> airtimesat_platform.gateway.sitest_port` and `airtimesat_platform.masker.** -> airtimesat_platform.gateway.sitest_port` | The masker reaches IWS only through its own port. The ignored edge also cuts the indirect chains through the port |
| New `masker-sitest-only` (forbidden, `allow_indirect_imports = false`): `forbidden_modules` = `airtimesat_platform.gateway.api` and `airtimesat_platform.gateway.endpoints_production`. A test pins the S4 production-endpoint module name, because import-linter skips forbidden modules that are not yet in the graph and would otherwise pass vacuously | A Beta or production endpoint in agent-reachable code is a defect (`CLAUDE.md`). `gateway.api` is the console's port and will reach production endpoints in S4 |
| `soap-libraries-gateway-only`: remove `masker` from its sources; new `masker-no-transport` forbids `aiohttp` and `xsdata` in the masker, with `allow_indirect_imports = true` | The masker needs `lxml` to mask; HTTP stays in the gateway. Indirect checking would fail on masker → `sitest_port` → `transport` → `aiohttp`. The contract comment already expects this change |
| New `gateway-no-masker`: the gateway never imports the masker | Keeps the dependency one way |
| New `console-not-sitest-port`: the console never imports `gateway.sitest_port` | Keeps the two ports apart |
| `tests/test_import_contracts.py`: update `EXPECTED`; replace `test_other_contracts_ignore_no_imports` with an explicit allow-list (`console-boundary`, `masker-isolated`); add `test_masker_may_only_skip_the_sitest_port` | The test pins the contracts and fails today on any `ignore_imports` outside `console-boundary`; it is on the mandatory review list |
| `CLAUDE.md` "Module boundaries": "`masker` imports only `common` and `gateway.sitest_port`; it may import `lxml`" | The written rule must match the contracts |
| `CLAUDE.md` "Live-system boundary": "The masker session token (environment variable `MASKER_TOKEN`, or injected for the masker host by the environment's Network secrets) is the only credential an agent may use. Never print, log, echo, commit or send it to any host other than the masker." | Today `CLAUDE.md` forbids agents to hold any credential and any secret in an agent session, so agents following it would refuse the token |
| `pyproject.toml`: add `aiohttp`, `lxml`, `boto3`, `asyncpg` (Apache-2.0; `psycopg` is LGPL-3.0 and would need a `licensing/exceptions.toml` entry with a written reason), `pyyaml` (wrapped in the strict loader of §8.1), `cryptography` if not already pulled in (runtime); `hypothesis`, boto3 type stubs (`types-boto3` or `boto3-stubs` for kms, secretsmanager and s3) and `lxml-stubs` unless the pinned `lxml` ships types (dev, for pyright strict) | Licence gate and pip-audit cover them; any licence exception needs a written reason |

All of these files are on the mandatory review list. They change in the S2 code PRs, not in this design.

### 12.4 Spike tests and the masker

The re-plan runs the S3 spike tests "with agents looping through the masker" (re-plan §4 S3; Annex F §7.2). Several pass criteria need what the masker refuses by design: bad signatures, skewed timestamps, wrong-case operations, more than one request in flight, PINs, large lists. The path per test:

| Test | Path |
|---|---|
| ST-15 | No IWS call; the CTO, before the first deploy (§15.2 step 2) |
| ST-01 | Offline, on the WSDL snapshot |
| ST-02 | Positive calls through the masker. Negative signatures, clock skew and operation-name case: the harness below. The wire `<timestamp>` hash: a transport test against a local TLS-terminating proxy, with no IWS call |
| ST-03 | Agents, on the masked infoset (masking keeps `xsi:type`, nil versus absent and arrays; §6.1). The ID and PIN round trip is judged on synthetic data, or by the CTO on one raw sample inside AWS |
| ST-04 | Agents through the write guard (S2b) on test inventory; DEACTIVE by the CTO (§8.5) |
| ST-07 | AUTH, FIELD, not found and empty success: through the masker (masked faults keep their shape). "Too many connections!": in a concurrency window, below |
| ST-05 | In a CTO-declared concurrency window with agents paused: the gateway prototype in AWS (the gateway role holds the secret) or the harness may use both permits and a third connection; results come back as counts and fault codes only |
| ST-08 | Metrics-only mode (§17 #6) for both the 10,000-row raw-usage page and the 5,000-row `accountSearch` |

**Harness (proposal, §17 #18).** A fixed, reviewed operation in the masker, callable only with a CTO token, that sends prebuilt request variants (bad signature, skewed timestamp, wrong-case operation, parallel requests) and returns only fault codes and timings, never a response body. It belongs to S3 scope; its review is not in §16 (about 1–2 CTO-hours, *Inferred*).

## 13. Secrets and keys

### 13.1 The SITEST secret

- Secrets Manager entry `airtimesat/<env>/iws/sitest` from the existing `modules/secrets`, encrypted with the secrets KMS key. Value (set by the CTO in the console, never in Terraform or git): `iwsUsername`, the secret key, and the SP account number(s).
- Readers: `reader_role_arns = { sitest = [<masker task role>] }`, plus the gateway role when it exists. Every read raises the existing alarm. The masker reads the secret once at startup and holds it in memory as a `SecretValue`, so each alarm means one start. Whether a signer sidecar holds it instead is §17 #17.
- **No Beta entry** in this account. The sandbox already defaults to `iws_credential_environments = ["sitest"]`. Because the same credential works on Beta, storing it under a "beta" name would add nothing but a second copy.
- The secret never reaches an agent session, a document, a log or git. Error messages name the secret, never its value (existing `SecretNotAvailableError`).
- **Rotation and compromise.** Rotation is manual (`resetIWSUserPassword` returns the new secret in clear text; dual-control runbook, Annex D §2.5) and is never available to agents. On suspected compromise: kill switch (§14.4), ask Iridium to rotate (procedure and lead time still to be obtained; re-plan §11.1 Q4), update the secret, restart. A SITEST secret leak is also a Beta leak, so the CTO treats it like a Sev1 (re-plan §8.1).

### 13.2 Masking and signing keys

| Key | Type | Who can use it | Purpose |
|---|---|---|---|
| `…-masker` | KMS symmetric, automatic rotation of the wrapping key | Masker role: `kms:Decrypt` with encryption context `{purpose: masker, env: sitest}`; CTO admin role: `kms:Decrypt` and `kms:GenerateDataKey` with the same context | Wraps `K_mask` (HMAC), the vault's AES-GCM data key, `K_req` (§8.3), the known-value hash key (§6.4) and the fixture key (§9), stored wrapped in the database |
| `…-masker-data` | KMS symmetric | Masker role: `kms:GenerateDataKey` (S3 `PutObject` with SSE-KMS); RDS through its service grant; CTO admin role: `kms:Decrypt` | RDS storage and the recordings bucket, kept apart from `kms_ops` so that the log key's readers cannot read recordings |
| `…-masker-tokens` | KMS asymmetric, ECC NIST P-256, sign and verify | CTO mint role: `kms:Sign`; masker role: `kms:GetPublicKey` | Session tokens (§3.3) |
| `…-masker-plans` | KMS asymmetric, ECC NIST P-256 | CTO approval role: `kms:Sign`; masker role: `kms:GetPublicKey` | Test-plan approvals and test-inventory rows (§8.1) |

The existing secrets key (`kms_secrets`) keeps encrypting the SITEST secret; its key policy delegates to IAM, so the masker task role needs `kms:Decrypt` on it, limited by `kms:ViaService` to Secrets Manager (§14.3).

Rotation: the token key can be replaced at any time (all tokens die, which is also a kill switch). The plan key on replacement invalidates every loaded plan and every signed inventory row, which the CTO then re-signs. `K_mask` is not rotated in normal operation (§6.3); after a suspected vault or key compromise the CTO generates a new one, which re-surrogates everything, and old fixtures are regenerated.

### 13.3 Making Beta unreachable although the credential works there

Layered, so that no single mistake reaches Beta:

1. **No Beta in the code.** The only IWS endpoints the masker can load are the two SITEST constants in `gateway/endpoints_sitest.py`. Beta and production URLs do not exist in any module the masker imports (`masker-sitest-only`, §12.3). There is no endpoint setting, environment variable or header that changes the destination. A test fails if a Beta or production host name appears anywhere under `src/` (from S4, except in `gateway/endpoints_production.py`, which `masker-sitest-only` keeps out of the masker's reach).
2. **Host pinning in the transport.** Before each send, the transport checks that the URL host equals the SITEST constant, follows no redirects, and verifies TLS for that host name.
3. **Startup self-test.** The masker refuses to start unless `iwstraining.iridium.com` resolves and a dedicated self-test label outside the DNS firewall's allow list (a fixed random label under `iridium.com`) does **not** resolve from its task. A failure raises an alarm. The DNS-firewall alarm excludes only that label, so every start does not trip the alarm that guards Beta. The Beta and production names themselves (`iwsbeta.iridium.com`, `iws.iridium.com`, `iws-report.iridium.com`) are checked once by the CTO at the S2a exit and after any firewall change, with the alarm expected (§15.1).
4. **DNS firewall.** A Route 53 Resolver DNS firewall rule group on the VPC allows the SITEST host and the exact AWS endpoint names the masker uses (never a wildcard such as `*.amazonaws.com`) and blocks all other names, Beta and production included. Blocked queries are logged and alarm. When the gateway later needs production in another account or VPC, that VPC gets its own rule group. This one changes only through a reviewed PR; any other workload placed in this VPC needs its names added explicitly.
5. **Egress port and address.** Security-group egress for the masker allows TCP 8443 only to the SITEST host's addresses (resolved and reviewed as a Terraform variable) and TCP 443 only to the VPC endpoints' security group and the S3 prefix list (§3.2). Whether SITEST and Beta share addresses is not known; ST-15 records the resolution of both. If they share an address, layers 1–4 carry the control and the CTO considers an SNI-filtering firewall, which costs far more (*Inferred*).
6. **Credential.** Ask Iridium for a SITEST-only IWS user for agent traffic (open decision §17 #5). With it, the masker would hold no credential that works on Beta at all.
7. **Review.** Every layer sits on the mandatory review list (gateway, masker, Terraform).

## 14. Operations

### 14.1 Hosting

| | ECS Fargate, one task, behind an ALB (recommended) | Lambda with a Function URL |
|---|---|---|
| Fit with the gateway | Same runtime, deploy settings and single-task pattern as the gateway (D2: one task, startup lock) | A second runtime model to maintain |
| Long IWS calls (up to 300 s; Annex D §2.5) | ALB idle timeout raised to 360 s | Up to 15 min per invocation |
| Connection limit to IWS | One process holds the 1-connection pool; deploy settings never run two tasks (§10) | Each invocation has its own; only the ledger and reserved concurrency cap them |
| Database connections | One pool | One per invocation, or RDS Proxy (extra cost) |
| Inbound path | ALB in two new public subnets; tasks stay private | Function URL outside the VPC; the VPC stays egress-only |
| Run cost (*Inferred*, us-east-1, 24×7) | Task 0.25 vCPU / 0.5 GB arm64 ≈ US$8; ALB ≈ US$18–24 incl. LCUs; two public IPv4 ≈ US$7 | ≈ US$1–3 |

**Recommendation: Fargate behind an ALB**, because it is the gateway's own pattern and keeps the 1-connection cap physical. Lambda is the fallback if the run cost decision (re-plan §12 #2, still open) pushes hard.

### 14.2 Run cost (*Inferred*)

| Item | US$/month |
|---|---|
| Fargate task | ≈ 8 |
| ALB with two public IPv4 addresses | ≈ 25–31 |
| RDS PostgreSQL single-AZ, smallest class, 20 GB, PITR (for the masker and the SITEST permit ledger; §17 #14) | ≈ 15–20 |
| KMS: 4 new keys | ≈ 4 |
| VPC interface endpoints: 6 (KMS, Secrets Manager, Logs, monitoring, ECR api and dkr) in the masker's one AZ; ≈ 90 in two AZs | ≈ 45 |
| S3 recordings and ALB access logs, CloudWatch logs and alarms, DNS firewall | ≈ 3–8 |
| AWS WAF with one rate rule (on by default, §14.3) | ≈ 6–8 |
| **Masker increment** | **≈ 105–125** in one AZ (≈ 150–170 in two; more in sa-east-1) |

The NAT gateway and its Elastic IP are already in the network module and shared. Stopping the task when agents are idle saves only the Fargate line. The interface endpoints are the price of closing the exfiltration paths of §3.2; the S3 gateway endpoint is free. The masker service is pinned to one private subnet so that one AZ of endpoints suffices. These figures count against the platform's open US$150–300/month estimate (re-plan §7).

### 14.3 Terraform outline (agents write it; the CTO reviews and applies it; never applied by agents or CI)

| Module | Contents |
|---|---|
| `network` (change) | TCP 8443 in the private NACL and in the `public_nat` NACL (ingress from the VPC CIDR, egress to the SITEST addresses); a masker security group (443 only to the endpoint security group and the S3 prefix list; 8443 only to the SITEST addresses); two public subnets for the ALB with their own NACL (443 in, ephemeral ports out, the container port to the private subnets); interface endpoints with private DNS and account-limited policies (§3.2); S3 gateway endpoint (free) whose policy allows only the recordings bucket and the ECR layer bucket; DNS firewall rule group (exact names only), association and query logging. The module header and its "public subnet holds the NAT gateway and nothing else" invariant are updated: the VPC now has one authenticated public ingress |
| `postgres` (new) | RDS PostgreSQL single-AZ, PITR, encrypted with `…-masker-data`, private subnets, security group open on 5432 only to the masker and the admin path (§17 #16); schemas `masker`, `masker_vault`, `masker_inventory`, `iws_permits` with separate roles; row-level security on `iws_permits`. Not shared with a production gateway (§17 #14) |
| `masker_keys` (new) | The four KMS keys of §13.2 and their key policies |
| `masker_service` (new) | ECS cluster, task definition (arm64, non-root, read-only root file system, ECS Exec off, image pinned by digest), service with `desired_count` variable, `minimumHealthyPercent` 0 and `maximumPercent` 100, pinned to one private subnet; task role (read the SITEST secret only; `kms:Decrypt` on the secrets key with `kms:ViaService` = `secretsmanager.<region>.amazonaws.com`; `kms:Decrypt` on the masker key with its context; `kms:GenerateDataKey` on the data key; `kms:GetPublicKey` on the token and plan keys; `s3:PutObject` on the recordings prefix; logs), execution role, log group (KMS, 90 days), ECR repository (immutable tags, scan on push). The CTO builds the image from a reviewed `main` commit and pushes it by digest; there is no CI push role in S2 |
| `masker_edge` (new) | Internet-facing ALB, ACM certificate for the subdomain, HTTPS listener with a modern TLS policy and no port-80 listener, idle timeout 360 s; health check on `/healthz` (exempt from auth, 200 with no body); access logs to a log bucket; WAF on by default with logging that redacts the `authorization` header, or a written checkov skip reason in the PR |
| `recordings_bucket` (new) | S3 with SSE-KMS (`…-masker-data`), versioning, lifecycle 90 days, TLS-only policy, block public access |
| `secrets` (use) | `reader_role_arns = { sitest = [masker role] }` |
| `alarms` (new) | §14.4 metrics to the existing SNS topic pattern |
| CTO roles (new) | Mint role and plan-approval role, each `kms:Sign` on one key; CTO admin role: database access (IAM database authentication) with writes to `masker_inventory` and the admin flags, `kms:Decrypt` and `kms:GenerateDataKey` on `…-masker` with its context, `kms:Decrypt` on `…-masker-data`, `s3:GetObject` on the recordings for export. All assumable only with MFA |

### 14.4 Monitoring, alarms and kill switch

**Alarms (to the CTO's email via SNS):** runtime detector block (any); unknown element (any); log-filter leak hit (any); DEACTIVE or always-refused attempt (any); `IDENTIFIER_NOT_ISSUED` burst; daily distinct-record budget or vault growth; "Too many connections!" (any); IWS `AUTH` fault (any: wrong or rotated secret, or clock skew); DNS firewall block (any name but the self-test label); secret read (existing); startup self-test failure; token verification failures burst; 5xx rate; task restarts; vault occupancy over 50%; in-prefix real value (§6.2); budget (existing).

**Kill switch.** The first two need only AWS APIs (console or CloudShell), so they work even if the database or the admin path is down:

1. Disable the token key (`kms:DisableKey`). With the public-key cache at 60 s or less, every token fails within a minute.
2. Set the ECS service `desired_count` to 0.
3. `masker-admin pause` sets the global flag through the admin path: every agent request gets `403`; permits are released. Per-method and writes-only flags exist too. Writes start **off** in every deploy. Revoking single tokens (`jti`) or all of them (the "not before" time) also goes through the admin path.
4. Remove the masker role from the secret's reader list (Terraform), so even a running masker cannot read the secret again.

Automatic trips: a runtime block disables the method; three blocks in an hour pause everything; a certification window pauses agents (§9).

## 15. Exit criteria, test plan and first live steps

### 15.1 Exit criteria

**S2a (opens agents read-only):**

1. All tests in §11.2 and §11.5 pass for every read method in the allowlist; `make check` green (lint, pyright strict, contracts with the §12.3 changes, tests, security with `leak_scan.py`, Terraform with checkov, workflows).
2. Recorded samples: the CTO's recording session (§15.2) covers every allowed read method and every service type present in SITEST's data, the runtime detector has zero hits, there are zero unknown elements, and the CTO has inspected the masked output by eye.
3. The in-prefix counter (§6.2) reads zero for every type: the reserved prefixes are absent from real data.
4. Beta unreachability and egress: the self-test passes in AWS; the CTO checks once that the DNS firewall blocks the Beta and production names (alarm expected); the test that keeps Beta and production host names out of `src/` passes; the egress red-team cases (§11.5 #17) pass from the task.
5. The kill switch works: key disable, scale-to-zero, pause and revoke tested once.
6. The CTO has reviewed every line of the masker (including the logging filter), the gateway signer core, the Terraform and the contract changes.

**S2b (enables writes):** the hard-block tests, plan-signature and scope tests, idempotency and dry-run tests pass; test inventory is registered and signed; the first plan is approved; one CTO-observed dry run, then one real write on SBD inventory, recorded and masked.

These meet the re-plan's S2 exit: leak tests green on recorded samples, and the CTO's line-by-line review.

### 15.2 First live steps (the CTO personally, in order)

The credential arrived on or before 20 Oct 2026. Until Secrets Manager exists it stays in the interim store; Keeper is the recommended one and the decision is due (S0 pack, section 7).

1. **Now, mandatory and first.** From a trusted machine, harvest both SITEST WSDLs, provisioning and reporting (re-plan §10, week 4). No call to Beta. This is a prerequisite for the S2a field map and allowlist (§6.5, §4.2). Optionally run one `authenticatedPing` on SITEST (WSDL Explorer or SoapUI) to confirm the credential works. One call at a time.
2. **When the AWS account exists.** Run the ST-15 network probe (no credential; S3 scope, counted here, §16.1) from the candidate regions; record RTT, TLS, and how `iwstraining` and `iwsbeta` resolve. Choose the region.
3. Review and apply the Terraform of §14.3 with `desired_count = 0`.
4. Paste the SITEST credential into Secrets Manager in the console. Confirm the read alarm reaches your inbox (it fires on the masker's first start).
5. Generate `K_mask`, the vault key and the other wrapped keys with `masker-admin keys init` through the admin path (§17 #16), with MFA.
6. Build the image from the reviewed `main` commit, push it by digest, and start the masker (`desired_count = 1`) with agent access paused. Check the startup self-test in the logs.
7. Mint a `read:catalog read:sp` token for yourself (masked like any other, §11.4). Run `authenticatedPing` and `getSystemStatus` on both endpoints through the masker.
8. **Recording session:** run the recording script (read allowlist only): system calls, one catalog cascade per service sold, `accountSearch` with `limit` 5 per service type, `getSubscriberAccount` on 2–3 accounts of each type present, `validateDeviceString` on assigned test inventory if any, `getIwsRequests` over the last hour. Read the masked output. Read the in-prefix counter (§6.2). Add the message templates the samples need (§6.4).
9. If anything leaked or is unknown: pause, fix, repeat 8. Otherwise mark the S2a exit.
10. Mint the first agent read token (§17 #12), set it in the dedicated SITEST cloud environment (§3.3), allow the masker host in that environment's network allowlist, and un-pause agent reads.
11. Later (S2b): register test inventory, approve the first plan, watch the first dry run and the first write.

## 16. Effort and schedule

### 16.1 CTO-hours (*Inferred*)

Agents write the code, tests, Terraform and the recording script. The CTO decides, reviews line by line and runs the live steps.

| Work | Low | Expected | High |
|---|---|---|---|
| Design review and the §17 decisions | 1.5 | 2 | 3 |
| Line-by-line review: masker read path, schema validation, tokenization, detectors, logging filter, recorder (about 2,000–3,000 lines with tests; about 220–330 lines/h at the expected 9 h) | 6 | 9 | 12 |
| Line-by-line review: gateway signer core and permit ledger | 1.5 | 2 | 3 |
| Terraform and IAM review, apply (including VPC endpoints, edge and admin path) | 2 | 3 | 4 |
| First live steps and recording session (§15.2, steps 1–10, including the ST-15 run) | 1.5 | 2.5 | 4 |
| **S2a subtotal** | **12.5** | **18.5** | **26** |
| S2b: write guard review (envelope rebuild, signed inventory, `accountUpdate` diff), inventory registration, first plan and first write | 3 | 4.5 | 6 |
| **S2 total** | **15.5** | **23** | **32** |

This is above the re-plan's S2 budget of 8 / 12 / 15. Moved from S3 (*Inferred*): the signer core and permit ledger review (2 h expected) and the ST-15 run (about 0.5 h), so S3 shrinks by about 2.5 h. The re-plan's 8 / 12 / 15 is not itemized, and the items here are *Inferred*; the hardening from the design review (egress endpoints, schema validation, envelope rebuild, signed inventory, logging filter) adds to them. Net of the transfer, S2 is about 20.5 h expected against 12: about 1.7 times the estimate, above the re-plan's 1.3x line (§3.5). That line is applied to actuals at week 8, but an estimate this far above it means §17 #9 must re-baseline S2 and S3 before work starts. The lines and CTO-hours of `gateway/signing.py`, `envelope.py` and `transport.py` written in S2 count toward the K8 budget of the owned SOAP layer (about 2,500 lines or 40 CTO-hours; Annex F §7.3). The CTO-hours log (re-plan §3.5) should record S2 hours separately from S3 so the week-8 calibration sees this.

**Split.** Agents: all code, tests, Terraform, fixtures pipeline, the recording script and the runbook draft. CTO: decisions, reviews, every AWS apply, the secret, keys, tokens, plans, inventory, every live call before S2a exit, and every DEACTIVE.

### 16.2 What the early credentials change

All dates below are *Inferred*.

- **S2 moves onto the critical path now** (S0 pack status note). Agents start S2a code on the catalog in weeks 2–3, before the AWS account exists; the field map and allowlist are finalized after the WSDL harvest (§15.2 step 1). The binding constraints become the AWS account (requested in week 3; S0 action 3.2) and CTO review hours, while S0 still needs 15–20 CTO-hours in weeks 1–3.
- **S2a exit:** week 5 (16–22 Nov 2026) at best, instead of the re-plan's week 5–6. That assumes the AWS account by the start of week 4 and about 15 CTO-hours in weeks 4–5, which is all build capacity at ~8 h/week (re-plan §4.1), with the design review and part of the code review done earlier. It leaves no room for S1 if TAP files are at risk. Week 6 is the more likely case. Agents then start S3 read work in week 6 at the latest.
- **S2b:** inside S3's first weeks, before ST-04.
- **S3:** the "no credentials by week 6" tripwire is moot. G1 stays expected in month 3 (mid-January 2027): the spike's tripwires are in CTO-hours, and the capacity check for months 1–3 (about 90 h available against about 100 expected for S0–S3; re-plan §4.1) is the real limit. Early credentials remove calendar risk; they do not add hours. If S2 runs at the expected 23 h, the months 1–3 gap widens by about 8–9 h (net of the 2.5 h moved from S3), which §17 #9 and the week-8 calibration must weigh before any date is re-stated.

No other stage is re-planned here.

## 17. Open decisions for the CTO

1. **Agent access path.** Recommend: HTTPS endpoint with CTO-minted, KMS-signed session tokens (§3.3, option A). Not mTLS (likely infeasible through the agent proxy), a tunnel or STS credentials.
2. **Hosting and run cost.** Recommend: ECS Fargate with an ALB, about US$105–125/month added in one AZ (*Inferred*), most of it the ALB and the VPC interface endpoints that close the exfiltration paths (§3.2, §14.2). This uses most of the low end of the open US$150–300 platform estimate. Fallback: Lambda with a Function URL at about US$22–34/month including RDS, plus the same endpoints (about US$45) if it gets the same egress controls.
3. **Masking scheme.** Recommend: keyed tokenization with a vault and reserved-prefix surrogates (§6.6). Not FF1.
4. **How the masker calls SITEST.** Recommend: S2 builds the gateway signer core and permit ledger, used through `gateway.sitest_port`, with the contract and `CLAUDE.md` changes of §12.3. Signer isolation is #17.
5. **A second SITEST IWS user for agent traffic.** Recommend: ask Iridium now (with the Annex D §2.4 request for `gs-cert` and `gs-ci`), and treat it as required before S5, because the User Activity Report cannot separate agent calls on a shared user (§9). It separates permits and evidence, and it takes Beta out of the masker's reach at the credential level. Until then, one shared user with the masker limited to permit B.
6. **Raw usage and inline reports for agents.** Recommend: refuse in S2. For ST-08 in S3, add a metrics-only mode (the masker makes the call and returns row counts, sizes, parse time and field presence, no rows) for both the 10,000-row raw-usage page and the 5,000-row `accountSearch` (§12.4). Decide on masked rows, with coordinates generalized, only after S2a has run clean.
7. **`CLOSED` treated like DEACTIVE, and the CTO's DEACTIVE path.** Recommend: yes, hard-blocked for every token, because it is terminal. The CTO's own DEACTIVE: a manual call from the trusted machine with the masker paused, recorded with `masker-admin note` (§8.5).
8. **Retention.** Recommend: call log 18 months; masked exchanges 90 days; vault values deleted 90 days after last use, with the slot kept forever as a tombstone; test-inventory rows never expire. Legal sets the final periods and confirms the basis for masked data in agent transcripts (§9).
9. **Split S2 into S2a (reads) and S2b (writes), accept the revised S2 budget** of 15.5 / 23 / 32 CTO-hours with about 2.5 h moved out of S3, **and re-baseline S2 and S3 before work starts**, because the net estimate is about 1.7 times the re-plan's 12 h (§16).
10. **WSDL snapshot and field-map location.** Recommend: bring the snapshot forward from S3 to S2 under `gateway/wsdl/`, with the generated field map under `gateway/wsdl/fieldmap/` (§12.2), because the field map is generated from it; `CLAUDE.md` says snapshots and generated bindings live under `gateway/` from S3. Subject to the interim confidentiality rule (re-plan §8.6).
11. **Endpoint name and certificate.** Recommend: a dedicated subdomain such as `masker.<globalsat-domain>` with an ACM certificate. Who controls Globalsat's DNS zone, and can it delegate a subdomain to Route 53? [FILL]
12. **Token lifetime and delivery.** Recommend: read tokens 4 h, write tokens 2 h or less (8 h is the alternative if minting twice a day is too much); set by the CTO in the dedicated SITEST cloud environment, as a Network secret if that keeps the value out of the session, otherwise as `MASKER_TOKEN`; never pasted into chat (§3.3). Minting takes a few minutes each time (*Inferred*), counted in S3 CTO-hours. Key-bound (DPoP-style) tokens: not in S2a, since a binding key in the session is as exposed as the token to a session compromise; revisit if a token ever appears in a log, a transcript or git.
13. **Agents paused during the S5 dry runs and the certification run.** Recommend: yes, automatically, with the evidence module voiding any window that shows an `agent.` caller, plus the calendar-month rule while agents share the IWS user (§9).
14. **RDS now, and no sharing with production.** Recommend: create the RDS instance in S2 for the masker and the SITEST permit ledger, rather than in S3; the S3 gateway prototype (SITEST only) may use it. The masker never shares a VPC, an RDS instance or a database role with anything that holds a production credential, so in S4 the production gateway gets its own VPC (preferably its own AWS account) and its own RDS (§3.1).
15. **Plan location.** Recommend: `test-plans/` in this repository, reviewed by PR, loaded and signed only with `masker-admin plan load`. Add the path to CODEOWNERS.
16. **Admin path to the database.** `masker-admin` writes to RDS (keys init, inventory add, plan load, pause, revoke), but RDS is private and default CloudShell runs outside the VPC. Options: (a) a CloudShell VPC environment in a private subnet with a `masker-admin` security group that the RDS security group allows on 5432 (verify it is offered in the chosen region); (b) `aws ecs run-task` of the admin image in a private subnet, only for commands without real values, because task overrides are recorded in CloudTrail; (c) an admin API on the masker that accepts only tokens signed by a separate KMS admin key, which adds code to the internet-facing path. Recommend: (a), with (b) as the fallback for `pause` and revoke.
17. **Signer isolation.** Today the masker process would hold the SITEST secret, which also works on Beta (§12.1). Options: (a) in-process, as designed; (b) a signer sidecar container in the same task: the task definition injects the secret only into that container (container-level `secrets`, read by the execution role), the task role cannot read the secret, and the masker calls the sidecar over localhost with the Annex D §2.1 interface; the sidecar re-checks the allowlist and the DEACTIVE hard block, injects auth, holds the permits, sends to the pinned host and returns only the response, never a signature or timestamp; (c) a separate SITEST gateway task (one more Fargate task, about US$8/month), which fallback A and the S3 prototype could also use. ECS gives one task role to all containers of a task, so in (b) the isolation comes from the secret injection, not from separate roles. Recommend: (b), decided before S2a code starts, because it changes §12.2 and §12.3 (the masker then calls the sidecar instead of importing `gateway.sitest_port`); about 1–2 more CTO-hours of review (*Inferred*). Residual risk: a compromised masker can make SITEST calls while it is compromised, but cannot take the secret to Beta.
18. **Spike-test harness.** Recommend: build the CTO-token-only harness of §12.4 in S3, returning fault codes and timings only, so that ST-02 negatives, ST-05 and the ST-07 "Too many connections!" case run without opening the masker's rules. Alternative: the CTO runs those cases by hand from the trusted machine.
19. **Read scopes for agent tokens.** Recommend: agent tokens default to `read:catalog read:inventory`. The CTO mints `read:sp` (SP-wide, with a lower daily budget, for example 200 records, *Inferred*) only for S3 tests that need SP-wide data, such as ST-03's "every account type present".
20. **`K_mask` inside KMS, and surrogate epochs.** Options: keep `K_mask` wrapped and unwrapped in task memory (as designed), or use a KMS HMAC key through `GenerateMac`, created inside KMS and never exported (one KMS call per identifier not yet seen in the response; latency and cost to measure, *Inferred*). Separately, a quarterly epoch in the derivation would make old surrogates stop resolving and stop linking, at the cost of breaking surrogates agents have saved. Recommend: the KMS HMAC key if the recording session shows acceptable latency; no epochs in S2, revisited with Legal's retention answer.
21. **Device swaps (`accountUpdateDevices`, device-changing `accountUpdate`).** Recommend: keep them out of S2b (§4.3). If a later test needs them, add a CTO-confirmed class: the plan lists each {from, to} pair under `irreversible:` with a dry run required, and the send needs a second CTO approval (`masker-admin approve-call <call-id>`). Record the old device's state in ST-04 first.
