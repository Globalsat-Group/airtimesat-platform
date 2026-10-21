# S2 design: recorder and masker

| | |
|---|---|
| **Status** | Restructured on 20 Oct 2026 for the CTO's option C (below). The VM form of this design was approved in principle earlier the same day; its decisions are kept for Part 2. No code is written until the CTO approves this revision and settles the open items in §13. |
| **Stage** | S2 of the delivery re-plan v1.2 (`Globalsat-Group/IWS`, `docs/delivery/DELIVERY_REPLAN.md`) |
| **Review** | On the CTO's mandatory line-by-line review list (re-plan §3.3; `CLAUDE.md`): the masker, the recorder (it writes to IWS), the gateway signer core, the leak tests, the import-linter contracts, and the `CLAUDE.md`, CODEOWNERS and CI changes this design proposes. Every recording plan is reviewed by the CTO before it runs (§9.2). Part 2, if activated, adds its provisioning files, Dockerfiles and alerter to the list. |
| **Sources** | Re-plan §3.1–3.5, §4 (S2, S3), §8.1–8.3, §8.6, §10. Phase 1 plan (`docs/phase1-iws-app/IWS_APP_PLAN.md`) §1.3, §4.2, §4.6. Annex D (`annexes/D_platform_architecture.md`) §1, §2.1–2.9, §6. Annex E §1.4, §2.2, §2.3, §5. Annex F §6, §7. IWS catalog (`docs/iws-catalog/`): `objects.md`, `methods_provisioning.md`, `methods_reporting.md`, `enums.md`, `overview_workflows_rules.md`, `reports_library.md`, `ux_questions.md`. This repository: `CLAUDE.md`, `pyproject.toml`, `tests/test_import_contracts.py`, `.github/CODEOWNERS`, `licensing/`, `src/airtimesat_platform/` (including `common/secrets.py`), `docs/SETUP_CHECKLIST.md`. The full VM design that Part 2 summarizes is the previous revision of this file (commit `f00407d`, §3, §4 and §9–§14). |
| **Confidentiality** | The IWS catalog derives from confidential Iridium documentation. This document names IWS methods and fields only. It copies no descriptions. Keep it in this private repository. |

S2 builds the masking engine and the recorder: the only path by which SITEST data reaches agents. SITEST is refreshed from production, so it is treated as production personal data (Phase 1 plan §0, finding 8; §4.2). In S2 the CTO runs every live call personally, from the trusted machine, and agents work only from masked recordings.

**Why this much security at the start.** The CTO asked why the design is so strict when the platform is just getting started. This revision answers with its shape. Four risks are irreversible from the first call, so their protections stay in Part 1: real personal data from SITEST, which cannot be recalled once it reaches an agent transcript, git or a cloud service; the one write-capable credential, which also works on Beta, where a leak waits on Iridium's unknown rotation lead time and a DEACTIVE burns inventory for good; AI agents, which can be steered by text planted in a repository, a web page or a SITEST free-text field; and Iridium's open confidentiality question (re-plan §8.6). Those protections are mostly code and review, and cheap. The expensive part was the infrastructure that let agents call SITEST live: an internet-facing VM, tokens, firewalls, an egress proxy, backups and alarms. That moves to Part 2, an optional add-on.

**Changes of 20 Oct 2026.** A short history of the day's decisions:

1. **First review.** The CTO accepted the first draft's recommendations in principle: keyed tokenization with a vault, the gateway signer core built in S2, the WSDL snapshot moved forward to S2, and a read part before a write part.
2. **Hosting and IWS user.** The agent endpoint was moved out of AWS to one VM at DigitalOcean, with one IWS test user shared with the CTO and no second user requested. S2 was re-baselined at 19 / 30 / 42 CTO-hours and accepted. Software keys in Keeper (no hardware keys) and a first recording that did not wait for Legal followed, then SSH only over Tailscale (no public SSH, replacing the per-session firewall rule), an automatic TLS certificate via Caddy and Let's Encrypt, alarms by e-mail to the CTO, and the CTO adding the subdomain record in Globalsat's DNS.
3. **Option C (this revision).** Agents no longer call SITEST live in S2. **Part 1 (S2 now):** the masking engine plus a recorder that the CTO runs on the trusted machine from reviewed recording plans; the vault stays encrypted on that machine; no VM, no internet-facing endpoint, no agent tokens and no run cost. **Part 2 (later, optional):** the live agent endpoint on one DigitalOcean VM, with a lean security profile, decided at the week-8 calibration (7–13 Dec 2026) if the CTO-run loop becomes the bottleneck (§12). The VM decisions of item 2 are kept for Part 2. The 19 / 30 / 42 budget is replaced by a Part 1 estimate of 8.5 / 12.5 / 18.5 (§11.1), which needs the CTO's acceptance (§13 #18). The accepted risk of SITEST data reaching DigitalOcean before Legal's review no longer arises in S2.
4. **Departure from the re-plan.** Re-plan §3.4 put the masker in Globalsat's AWS account, and re-plan §4 (S3) has agents looping through it. In S2, masking runs on the CTO's trusted machine, and in S3 agents loop through recordings and a simulator, with live experiments as recording plans the CTO runs (§9.3). The production gateway (S4) stays in AWS.

Conventions: *Inferred* marks an estimate or a design choice with no calibrated source. "Uncertain" marks something the sources do not settle. Every example value is fake and shows the surrogate format, never a real identifier. Section numbers run through both parts; the decisions list (§13) is numbered afresh in this revision.

## Part 1: S2 now (masking engine and CTO-run recorder)

## 1. Goal and scope

**Goal.** Give agents realistic, masked IWS data from SITEST, without any agent ever seeing a real identifier, holding an IWS secret, reaching SITEST, Beta or production, or writing to IWS. The CTO runs every live call, from reviewed plans, and nothing leaves the trusted machine unmasked.

**What S2 delivers.**

| Part | Reads (opens agent work on recordings) | Writes (before ST-04) |
|---|---|---|
| Masking engine | Consistent keyed tokenization of every identifier with a vault and reserved-prefix surrogates; a fail-closed field map generated from the WSDL; free-text and embedded-payload handling (§3, §4) | Unmasking of surrogates in write requests, scoped to test inventory (§5.5, §5.6) |
| Recorder | A CLI the CTO runs on the trusted machine; reviewed recording plans in git; read allowlist, always-refused list, default deny (§5) | Plan-scoped writes on assigned test inventory, dry run first, confirmed per write; DEACTIVE hard block (§5.6, §5.7) |
| Vault | Encrypted SQLite on the trusted machine, keys in Keeper, encrypted off-machine backup (§6) | Test-inventory table |
| IWS access | The gateway signer core under `gateway/`, called in process through `gateway.sitest_port`; pinned SITEST host; one connection (§7) | Same, with a second, independent hard-block check |
| Leak gate | Detectors, per-shape tests, runtime block, leak scan and gitleaks before git (§8) | Request-side detector for writes |
| Agent side | Masked recordings in git, the simulator built from them (S3), recording-plan PRs checked in CI (§9) | Same |

The re-plan's S2 exit is unchanged: leak tests green on recorded samples, and the CTO has reviewed the code line by line (§10). The write part must pass before ST-04 (polymorphic write and the SBD lifecycle, Annex F §7.2), the first spike test that writes.

**Not in S2.** No VM, no internet-facing endpoint, no agent tokens and no run cost: the live agent endpoint is Part 2 (§12). The IWS permit ledger goes back to S3 with the gateway prototype (§5.8). Also later: the full operation registry for all 177 methods and the CI rule on unclassified WSDL operations (Annex D §2.1); the typed client and xsdata bindings (ST-01); lanes, aging, breaker and fault normalization (Annex D §2.4–2.7); the gateway service and its production endpoint (S4); HA (deferred, D2); the evidence module (S4); masking of raw-usage rows and inline report rows (§13 #8); the IWS simulator, which agents build in S3 (§9.1); the spike-test harness (§9.3).

**Non-goals.** No production. No Beta, ever (Beta is CTO-only; CTO decision, 20 Oct 2026). No DEACTIVE through the recorder. No real CDRs, TAP files or customer exports. No unmasking for agents. No bulk export of SITEST data (row caps, plan call caps and a per-run record cap, §5.3). No UI. No HA.

## 2. Threat model for the recorder setup

### 2.1 Assets

| Asset | Why it matters |
|---|---|
| SITEST IWS secret | One development credential covers SITEST **and Beta** (decision, 20 Oct 2026). A leak of the SITEST secret is also a leak of Beta access. Iridium's rotation procedure and lead time are not known yet (re-plan §11.1 Q4; Annex B Q24). In Part 1 it exists in the CTO's Keeper and, during a live run only, in the recorder's memory. |
| Personal data in SITEST | A copy of production: IMEI, ICCID, IMSI, MSISDN, names, emails, vessel contacts, locations (Phase 1 plan §4.6, "Personal data and PIN"). In Part 1 a raw response exists only on the trusted machine: in the recorder's memory until it is masked, or on screen and in the tool files of the CTO's manual calls (§6.5). |
| Write capability | Writes change SITEST state. DEACTIVE is irreversible: SIMs are not recycled, MSISDNs and IPs go into 60-day quarantine (catalog `overview_workflows_rules.md`, Rules). Test inventory is scarce: about 3 full runs are requested (re-plan §11.1 Q10). Some writes act on every matching contract in the SP (`manageDestinations`; Phase 1 plan §4.6). |
| The two IWS permits | A third concurrent request is rejected (catalog Rules; Annex D §2.4). The recorder uses one connection, so the CTO's own call keeps the other slot (§5.8). |
| Masking keys and the vault | The vault maps surrogates back to real values. Whoever reads it with its key can de-pseudonymize every recording. Numeric types have little entropy (an IMEI with a known TAC has about 10^6 candidates, *Inferred*), so `K_mask` alone lets an attacker rebuild the mapping by brute force: a `K_mask` compromise equals a vault compromise for those types. Both stay on the trusted machine and in Keeper (§6). |
| IWS signatures | The signature covers only the operation name and the timestamp (catalog signature algorithm). A leaked (operation, timestamp, signature) triple can be replayed with any body against SITEST or Beta within IWS's clock-skew tolerance, which is still unknown (Annex D open questions). The signer core never returns it, and redacts any echo of it (§7.1). |
| Masked recordings in git | Pseudonymized personal data while the vault exists. They carry vault surrogates, so agents can name records in later plans (§4.3). Agent transcripts that read them are pseudonymized data too, held by the agent provider. |
| Certification evidence | The evidence must match the `getIwsRequests` extract one to one (Annex E §2.3). Recording calls must be told apart from certification calls (§5.8). |
| Iridium's confidential material | The WSDL snapshot, field names and the response shapes in masked recordings. Iridium's confidentiality question is still open (re-plan §8.6; §13 #23). |

### 2.2 Actors and what each failure would leak or break

| Actor | Can do | Worst outcome without controls | Controls (section) |
|---|---|---|---|
| **Honest agent** (bugs, misunderstandings), writing code and recording plans | Open code PRs, recording-plan PRs and override proposals | A masking bug that lets a real value into a recording; a plan that asks for too much data or writes to the wrong line | Fail-closed field map and runtime detector (§4.5, §8.4); leak scan and gitleaks before git (§8.3); `recorder check` in CI and the CTO's plan review (§9.2); plan caps (§5.3); write checks (§5.6) |
| **Prompt-injected agent** (instructions planted in a repository, a web page, an issue, or a SITEST free-text field such as a vessel name or `spReference`) | The same, chosen by the attacker; while agent sessions reach GitHub as the CTO's account (`docs/SETUP_CHECKLIST.md`, step 7b, Limit), also merge into `main` | A plan built to echo or enumerate real values; an SP-wide or DEACTIVE write; a code change that adds a Beta endpoint, writes raw responses or weakens a detector; an override that keeps a string field; plan or runbook text that asks the CTO for a manual DEACTIVE or Beta call; a self-merged plan or recorder change that the CTO then runs as reviewed | Agents never hold the secret, a raw response or a connection to IWS; the CTO checks every merge on `main` before running it (§6.5); manual calls follow the CTO's runbook, never a plan or an agent's message (§5.7, §9.2); free text is tokenized as a whole unless it matches a reviewed template (§4.1), which also strips most injection text from recordings; plans are strict YAML with call caps, and every surrogate must be issued (§5.2, §5.5); the allowlist and hard blocks are code (§5.3–§5.7); every masker, recorder and gateway line is CTO-reviewed; a test keeps every Iridium host but SITEST out of `src/` (§7.1) |
| **Malicious or vulnerable dependency** in the recorder's environment | Run as the CTO's OS user during a run | Read the secret and raw responses in memory and send them anywhere | Few runtime dependencies on the IWS path (`lxml`, `aiohttp`, `cryptography`, `pyyaml`), pinned and hash-checked in `uv.lock`, with pip-audit and the licence gate; installed in their own venv from the reviewed commit (§6.5); new dependencies only through a reviewed `pyproject.toml` |
| **Compromised trusted machine** (malware, an AI agent running as the CTO's OS user, here or on any other device where the CTO's Keeper is unlocked) | Whatever the CTO's OS user can do | Everything in Keeper (the secret and every key), the vault while unlocked, raw responses during a run, and SITEST and Beta calls outside every recorder control, DEACTIVE included | §6.5: one named device, full-disk encryption, no AI agent under the OS user that holds Keeper or as an administrator, the masker-keys and SITEST records unlocked only where no AI agent runs, only reviewed code from `main`, a minimal venv, keys loaded only for a run. The exposure is the same as before option C, because the secret already lived in Keeper on this machine. Residual risk accepted (software keys, §13 #14) |
| **The CTO** (trusted, part-time, fallible) | Everything | Running an unreviewed plan; pasting raw output into an agent chat; committing an unmasked file; a manual call that collides with a run | Live runs only from a clean checkout of a commit on `main` (§5.1); the recorder writes masked output only and has no raw mode (§8.4); leak scan and gitleaks in the pre-commit hook and again in CI over the PR range (§8.3); one connection (§5.8) |
| **Someone with read access to the repository** (a stolen GitHub account, a future collaborator, a GitHub incident) | Read recordings and plans | Pseudonymized SITEST data: shapes, statuses, dates, counts, surrogates | Surrogates resolve only in the vault on the trusted machine; reserved prefixes make them recognizably non-real; quasi-identifiers are dropped (§3.1); private repository |
| **Someone who takes the off-machine vault backup** | Read the backup file | Nothing without the backup key | Encrypted with age to a key held in Keeper and the offline escrow; the values inside are encrypted again with the vault key (§6.3) |

Option C removes the cases that came with the internet-facing endpoint: unauthenticated traffic, a stolen agent token, a compromised TLS front end, root on the VM and access through the hosting provider. They return with Part 2 (§12.3).

## 3. Identifier inventory

Every field below carries a personal or account identifier, a secret, or free text. The treatment codes are defined in §4.1. Source files are in `Globalsat-Group/IWS`, `docs/iws-catalog/`: **[O]** `objects.md`, **[MP]** `methods_provisioning.md`, **[MR]** `methods_reporting.md`, **[RL]** `reports_library.md`, **[E]** `enums.md`, **[OW]** `overview_workflows_rules.md`. Field names follow the catalog; the live WSDL is the source of truth (catalog README), so the field map is regenerated from the WSDL in S2 (§7.2).

### 3.1 By identifier type

| Type | Fields: objects and methods | Report columns [RL] | Treatment | Notes |
|---|---|---|---|---|
| **IMEI** | [O] `accountSearchReportImpl.imei`; `devicePairImpl.deviceImei`; `deviceImeiImpl.deviceNumber`; `imei`/`Imei` on the Burst device, Certus, M2M+, OpenPort, PTT device, SBD and telephony base account objects; `pttDeviceDetailImpl.Imei`; Burst service `Subscribers`/`Subscriber.Imei`; `vesselLinkImpl.IMEI`; `sbdDestinationSearchReplaceEntryImpl.imei`; `voucherActivityImpl.imei`; `sbdmtActivityImpl`/`sbdmoActivityImpl` `imei`; `imei` in the bulk details `m2MBulkDetailImpl`, `sbdBulkDetailImpl`, `telephonyBulkDetailImpl`, `pttDeviceBulkDetailImpl`; `deliveryDestinationImpl.destination` when `deliveryMethod` is `IRIDIUM_DEVICE` (§3.2); `loadImeiErrorDetailImpl.device`; `imei` in `certusRawCallDataEntryImpl`, `iopRawCallDataEntryImpl`, `sbdRawCallDataEntryNewImpl`, `subscriberCallDataEntryImpl`, `telRawCallDataEntryImpl`. [MP] `loadIMEI` `Devices[].Device`; `deviceTransferOwner` `bulkDetails[].bulkDeviceString`; `searchSimLock.imei`; `subscribeBurstService.imei`, `unsubscribeBurstService.imei`; `associateSimToImeiDevice`/`disAssociateSimFromImeiDevice` `deviceImei`; `deviceTransferOwner.deviceString`; `validateDeviceString.deviceString`, `fromDeviceString`; `setSubscriberAccountStatus.value` when `updateType` is IMEI; `accountSearch.filterValue` and `details`. [MR] tracker `memberId` (`memberTypeEnum` IMEI); `updateResourceGroupMember.devices`; raw-usage criteria `value` (`resourceType` IMEI) | IMEI in Account Sync, Burst Service, Certus IMEI Registration, Certus IP Data Services, Certus Raw Usage, Device Destination, Device Setting Detail, M2M Device Search, MT Filter, OpenPort Raw Usage, SBD Device Search, SBD Raw Usage Summary and New, every Subscriber History and Subscriber Report except Paging, Subscriber Usage Summary, Telephony Raw Usage, Voucher Usage Details | T-NUM | 15 digits; SBD/M2M+ IMEIs start with 3 and end with 0 [OW]; no check digit assumed (catalog example IMEIs fail Luhn). `imeiProfileImpl.tac`/`fac` are model prefixes, kept |
| **ICCID (SIM serial)** | [O] `accountSearchReportImpl.iccid`; `deviceSimImpl.deviceNumber`; `devicePairImpl.deviceSim`; `sim`/`Sim` on Certus, OpenPort and telephony accounts; `vesselLinkImpl.Sim`; `prepaidAccountDetailImpl.iccid`; `m2MBulkDetailImpl.sim`, `telephonyBulkDetailImpl.sim`; `deviceSwapImpl.fromDevice`/`toDevice`; `restrictedDeviceSwapImpl.oldDeviceNumber`/`newDeviceNumber`; `iccid` in `subscriberCallDataEntryImpl`, `telRawCallDataEntryImpl`. [MP] `deletePrepaidAccount.iccid`, `getRechargeHistory.iccid`, `refundPrepaidVoucher.iccid`, `getPrepaidAccountSummary.subscriberitem` (MSISDN or SIM), `accountUpdateDevices.fromDevice`/`toDevice`, `accountSearch` (`SIM_SERIAL_NUMBER`), `setSubscriberAccountStatus.value` (SIM) | SIM (ICCID) in Account Sync, Certus, OpenPort and Telephony Raw Usage Summary, Pin Puk, Prepaid Account Summary, Subscriber History and Report (ATS, All, Certus, M2M, OpenPort, Telephony), Subscriber Usage Summary; SIM in Telephony Raw Usage; Pin Puk Start/End Range parameters | T-NUM | 19 digits [OW]. Check digit assumed Luhn (*Inferred*; verify on recordings) |
| **IMSI** | [O] `deviceSimImpl.imsi`; `voucherActivityImpl.imsi`; `imsi` in the Certus, IOP, subscriber and telephony CDR entries. [MP] `bulkAddPrepaid`/`bulkDeletePrepaid` `telephonyImsis`; `accountSearch` (IMSI). [MR] tracker and resource-group members (IMSI); raw-usage `resourceType` IMSI | IMSI in Account Sync, Certus, OpenPort and Telephony Raw Usage (and Summaries), Device Destination, Device Setting Detail, M2M Device Search, MT Filter, Pin Puk, Prepaid Account Summary, Resource Inventory, Subscriber History and Report (ATS, All, Certus, M2M, OpenPort, Telephony), Subscriber Usage Summary, Voucher Usage Details | T-NUM | 15 digits [OW] |
| **MSISDN and other numbers** (MSISDN-B/C, ISDNA, PLUS1/PLUS7, local numbers, follow-me) | [O] telephony base account `msisdn`, `msisdnb`, `msisdnc`, `plusNumber`, `localCountry`; M2M+ `msisdnc`, `msisdnb`; `deviceNumberImpl.deviceNumber`; `openPortDeviceNumberImpl.deviceNumber`, `plusOneNumber`; `certusDeviceNumberImpl.deviceNumber`, `localNumber`; Paging `isdna`, `followMePagingNumber`; `localCountryImpl.deviceNumber`; `prepaidAccountDetailImpl.msisdn`; `voucherActivityImpl.msisdn`; `deviceErrorImpl.deviceNumber`; `removeDIDWWErrorDetailImpl.device`. [MP] `msisdn` in `deletePrepaidAccount`, `getPrepaidAccountDetail`, `rechargePrepaidAccount`, `refundPrepaidVoucher`, `getRechargeHistory`, `resetTelephonyVMPin`; `unquarantineDevice.deviceNumber`; DIDWW `localNumber`; `validateDeviceString` (types in `deviceStringTypeEnum` [E]); `getDevices` `num` results | MSISDN in Certus, OpenPort and Telephony Raw Usage, Prepaid Account Summary, Prepaid Call History, Subscriber Usage Summary, Voucher Usage Details; Line N MSISDN and Line N Local Number in Subscriber History and Report (ATS, All, Certus, M2M, OpenPort, Telephony); FMP MSISDN, Plus Num and Number Details Array in Account Sync; MSISDNC in Device Destination, Device Setting Detail, M2M Device Search, MT Filter; ISDNA and Follow Me MSISDN in Subscriber History and Report Paging | T-NUM | MSISDN: 12 digits starting 8816/8817 [OW]. Other number formats undocumented (uncertain) |
| **Called and calling numbers** | [O] `voucherActivityImpl.calledNumber`; `certusRawCallDataEntryImpl.callingFrom`/`callingTo`/`dialedNumber`/`shortCode`; `iopRawCallDataEntryImpl.callingFrom`/`callingTo`; `subscriberCallDataEntryImpl.callingNum`/`calledNum`; `telRawCallDataEntryImpl.aNumber`/`bNumber`/`calledNumber`/`callingNumber` | Calling From, Calling To, Dialed Number, Short Code (Certus Raw Usage); Calling From/To (OpenPort Raw Usage); A Number, B Number, Called Number, Calling Number (Telephony Raw Usage); Called (Prepaid Call History); Called Number (Voucher Usage Details) | P-ONE | Only in refused methods in S2. Third parties' numbers, not just subscribers' |
| **Capcode** | [O] Paging `Capcode`; `deviceCapcodeImpl.deviceNumber`. [MP] `validateDeviceString` (CAPCODE); `setSubscriberAccountStatus.value`; `accountSearch` (CAPCODE) and `details` | Capcode in Account Sync; CapCode in Subscriber History and Report All; Capcode in Subscriber History and Report Paging | T-NUM | Format undocumented (uncertain). Paging is likely N/A (Annex E §2.2) |
| **IP addresses, hosts, subnets, VPN names** | [O] Certus and OpenPort `ip`/`Ip`, `publicIP`; `deviceIpImpl.deviceNumber`; `deviceNumberImpl.deviceNumber` (can be an IP); `deliveryDestinationImpl.destination` (typed by `deliveryMethod`, §3.2); `mtFilterImpl.address` (typed by `ruleType`, §3.2; wildcards); `sbdmoActivityImpl.Destination`; `moipQueueReportEntryImpl.deliveryTo`, `deliveryPort`; `secondaryDataServiceImpl.subnetValue` (and `subnetMask`, kept); `deviceApnImpl.vpnName`, `deviceApnImpl.deviceNumber` (VPN id, IP-like), `openPortSubscriberAccountImpl.vpnId` (T-STR); `outputSettingsEntryImpl.deliveryAddrs` when an FTP/SFTP host or S3 bucket (T-HOST), `deliveryPath` (T-STR); `ipAddress` in the Certus, IOP and subscriber CDR entries; SBD `d1..d5` `DeliveredTo`/`DeliveredToPort`. [MP] `sbdMOQueuePurge.address`, `sbdMOQueueReport.address`; `manageDestinations` `oldDestination`/`newDestination`; `sbdDestinationSearchReplace` `oldValue`/`newValue`; `getDevices` `ip` | IP Addr and Public IP (Account Sync); IP Address, Public IP Address, Data Network Name (Subscriber History and Report All, Certus, OpenPort); IP Address (Certus, OpenPort Raw Usage); Destination and Delivery Address N (Device Destination, Device Setting Detail, M2M Device Search, SBD Device Search, Subscriber History and Report SBD, M2M, All); Filter Address N (Device Setting Detail, MT Filter); Delivery N Destination/Port (SBD Raw Usage New) | T-IP, T-HOST, T-STR | Delivery destinations are customer servers or mailboxes. Ports kept. `deviceApnImpl.routingInfo` is an int, kept |
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
| **Free text** | [O] `subscriberAccountMetadata.spReference` (every account type); `description` (many objects); `statusDescription`; `errorMessage` (`iwsLogImpl`, `baseQueueEntryImpl`, `addDIDWWNumberInventory`); `VesselContactInfoImpl.otherInfo`; tracker `subject`, `body`, `emailBody`; email profile `msgSubject`, `msgBody`; pooling group `Description`; `returnMessage`, `Message`; SBD `metadata`; `outageReason` and outage `description`; `valid*DeviceDataImpl.reason`; `reportTransactionLogEntryImpl.internalErrorDescription`, `externalErrorDescription`; `serviceProviderImpl.messageText`; `userImpl.accessInfo.userPrefs`. [MP] `setSubscriberAccountStatus.reason`. SOAP fault reason and detail text | SP Reference (Account Sync, Subscriber History and Report, Subscriber Usage Summary); Description | F; `spReference` and customer-entered descriptions → T-STR (§4.4) | IWS echoes request values in error text (catalog error tables). `spReference` is searchable (`PROVIDER_REFERENCE` [E]), so it is reversible |
| **Other IDs and file names** | [O] Certus `messagingServiceDetail.cmid`; `deviceId` on every device object (`deviceCapcodeImpl`, `certusDeviceNumberImpl`, `deviceSimImpl`, `deviceImeiImpl`, `deviceNumberImpl`, `deviceIpImpl`, `localCountryImpl`, `deviceApnImpl`; uncertain: a billing resource id); `subscriberAccountEntryImpl.deviceDetails`; `topicImpl` `queueSetId`; `fileListEntryImpl.fileName`; `certusRawCallDataEntryImpl.sdfName`; `telRawCallDataEntryImpl.sourceNetwork` (uncertain); `sbdRawCallDataEntryNewImpl.mtFilename`. [MR] `getFileList.requestName` | Download File Name (SBD Raw Usage New); SDF Name (Certus Raw Usage) | T-STR | These match no pattern detector, so the field map is the only control (§4.5) |
| **Embedded payloads** | [O] `iwsLogImpl.request`, `response` (escaped XML); `baseQueueEntryImpl.request`, `response`; `reportResultDetailsEntryImpl.row` (CSV); `createOnDemandReport.link` [MR]; `fileListEntryImpl.fileDownloadURL` | Delivery Array, Filter Array (Account Sync); Devices Array, TalkGroup Array (IWS getSubscriberOrg) | N for XML, CSV and arrays; D for URLs | A download URL is a bearer link to the full report (Annex D §2.8) |
| **Secrets** (always dropped) | [O] `signature`, `callerPassword`, `didwwUserApiKey`, `userImpl.password`, `CertusScratchcardImpl.pin`, `scratchCardDetailsImpl.pin`, `scratchCardsDetailEntryImpl.pinNumber`, `prepaidAccountDetailImpl.pinNumber`, `captainPin`, `twoStagePin` (Certus voice line, OpenPort phone line, `twoStageImpl`), Burst `dpName`, `dpPassword`, `spName`, `spPassword` (the names are the logins paired with those passwords), `outputSettingsEntryImpl.deliveryUserKey`, `deliveryPwSecret`, `vesselImpl.gmdssPw` (uncertain). [MP] `resetIWSUserPassword.newPassword`; `resetUserPassword.Token`, `Password`; `userAuthenticate.password`; `resetTelephonyVMPin.newValue`; `updateTopicAssociation.associationKey` | Pin 1, Pin 2, Puk 1, Puk 2 (Pin Puk); PIN (Prepaid Account Summary, Voucher Details, Voucher Usage Details); Line N 2 Stage PIN, Line N Captain PIN (Subscriber History and Report) | D | Masked in Annex D §2.8 already; the masker removes them before anything else |

### 3.2 Identifier-typed parameters

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

## 4. Masking scheme

### 4.1 Treatments

| Code | Treatment | Reversible by the masker | Used for |
|---|---|---|---|
| T-NUM | Keyed tokenization into a digit surrogate of the same length (a fixed length for number types of unknown format, §4.2), in a reserved prefix, with a valid check digit where the type has one | Yes, through the vault | IMEI, ICCID, IMSI, MSISDN family, capcode, `SUB-`/`SC-` numbers, IMO, MMSI, 19-digit serials, numeric-typed IDs |
| T-STR | Keyed tokenization into a labeled string, `<Label>-<8 base32 chars>`. On an element with a numeric XSD type it becomes T-NUM | Yes | Vessel, organization and group names, `spReference`, customer-entered descriptions, VPN names, other IDs |
| T-IP | Keyed tokenization into a reserved address range | Yes | IPv4, IPv6, subnets |
| T-HOST / T-EMAIL | Keyed tokenization under the reserved domain `example.invalid`; `*` wildcards and ports kept | Yes | Delivery hosts, filter domains, emails |
| P-ONE | One-way pseudonym with the same derivation, no vault row | No | Person names, logins, contact phones, postal address parts, called and calling numbers |
| C | Constant per distinct real value | No | SP account numbers and names, `iwsUsername` |
| G | Generalize | No | Coordinates (1 degree); later, if allowed, vessel build year (decade), tonnage and capacity (bands) |
| D | Drop: on a string element the value is replaced by `REDACTED` and the element kept, so the shape stays; other types follow the XSD rule below | No | Secrets, PINs, PUKs, download URLs, LAC, altitude, vessel quasi-identifiers |
| F | Free text: replaced as a whole by `Text-<8>` (P-ONE derivation, no vault row) unless the value fully matches a reviewed message template, whose typed slots are masked by type (§4.4) | No | Error messages, fault text, reasons, system and catalog descriptions |
| N | Parse the embedded XML or CSV and mask it with the same rules; drop it if it does not parse | — | IWS log and queue payloads, inline report rows |

**Every output must be valid for the element's XSD type** in the field map, so agents' bindings and strict validation keep working. D on a numeric or date element writes `xsi:nil` if the element is nillable; otherwise it removes the element if `minOccurs` is 0; otherwise it writes a type-valid sentinel listed in `overrides.yaml`. T-STR on a numeric type becomes T-NUM. G keeps the type.

Values are kept only where the field map says keep (§4.5): dates, statuses, enums, plan and bundle IDs, catalog names, counts, flags.

### 4.2 Surrogate formats

The reserved prefixes are tentative. Each must occur in **zero** real values of its type in SITEST. Only the masker sees real values, so it checks this itself: when issuing a surrogate, it counts real values that fall inside the type's reserved prefix, refuses to issue for them and writes an incident (count only, never the value). The first recording session (§10.2) reads this counter, and so does every detected SITEST refresh (§5.6). If a prefix does occur, the masker uses the next candidate, and the change is a reviewed constant.

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

Why these shapes: the same length (where the real length is fixed) and digits keep agent code, XSD types and lengths working; the reserved prefix makes every surrogate **recognizably non-real**. Real values can start with `99` too (for example 12-digit numbers under the assigned E.164 codes 992–996 and 998; general knowledge), so the leak detector exempts only surrogates the masker itself placed in the response, never a value just because of its prefix (§8.1). Domains and address ranges are reserved by standards (`example.invalid`, `240.0.0.0/4`, `2001:db8::/32`; general knowledge, not from the sources). Surrogates that break IWS's own format rules (for example an MSISDN that does not start 8816/8817) are fine: IWS only ever sees real values. Agent tests of format validation use synthetic data, not surrogates.

### 4.3 Derivation, consistency, collisions and check digits

- **Derivation.** `h = HMAC-SHA256(K_mask, TLV(type) || TLV(version) || TLV(real_value) || TLV(counter))`, where each field is length-prefixed, so distinct inputs never concatenate to the same string. The digits or base32 characters of the surrogate body come from `h` (digits: `h` as an integer modulo `10^n`). `type` keeps an IMEI and an IMSI with the same digits apart, and every type is derived independently. `counter` starts at 0.
- **Consistency.** The derivation is deterministic, so the same real value gets the same surrogate in every call and every recording run, for as long as `K_mask` and its vault row exist. Consistency is global, not per run, and agents rely on it: committed recordings keep their vault surrogates, so a record seen in one recording can be named in the next plan (§9.1). After a SITEST refresh, values that survive keep their surrogates, but write scope is reset (§5.6).
- **Vault.** Every reversible surrogate issued has a row: `(type, surrogate, counter) → AES-256-GCM(real_value)`, plus first-seen and last-seen times. The vault is the record of what the masker issued (§5.5). It lives on the trusted machine (§6.1). Expired rows become tombstones whose slot is never reused (§6.4). A tombstone no longer records which value it held. So a value that returns after its row was deleted gets a **new** surrogate, at the next free counter. The old surrogate stays reserved forever, so it never comes to mean another value (§13 #30).
- **Collisions.** On issue, the masker looks up `(type, surrogate)`. If the row holds a different value, or is a tombstone, it increments `counter` and derives again. Collisions are expected, not rare. Surrogate space per type (*Inferred*): `SUB-` 10^6 (about 500 expected collisions at the assumed ~32,000 contracts, Annex D §2.4); IMO 10^4; `SC-` 10^(digits − 2); MMSI 10^7; MSISDN and other numbers 10^10; IMEI 10^12; IMSI 10^13; ICCID 10^16. The masker refuses to issue past 50% occupancy of a type's space (tombstones count) and stops the run with an incident (*Inferred* threshold); for IMO and short `SC-` numbers that cap is reachable, and the CTO then approves a longer or second prefix.
- **Check digits.** Recomputed for the surrogate (Luhn for IMEI and ICCID). The real value's check digit is never copied.
- **Key.** `K_mask` is a 256-bit random key the CTO generates once on the trusted machine (`recorder keys init`). Keeper holds it, with an offline escrow. It is loaded into the recorder's memory from Keeper for each run, never into a file, an environment variable or a log (§6.2). It is never rotated in normal operation, because rotation changes every surrogate. Surrogate epochs are not in S2 (§6.4).

### 4.4 Free text, embedded payloads and faults

- **Known-value replacement.** For each call, the masker keeps the set of real values it replaced in structured fields, the real values it put into the request (§5.5), and the auth values injected for the call (`iwsUsername`, `serviceProviderAccountNumber` and the signed timestamp, which the signer core passes back; the signature never leaves the signer core, which redacts any echo of it before returning the response, §7.1). It then replaces any occurrence of those strings in free text, fault text and embedded payloads with the matching surrogate, constant or `REDACTED`. This catches IWS error messages that echo the request value.
- **Cross-call known values.** The masker keeps a keyed-hash set (HMAC with its own key, held like `K_mask` (§6.2), no plain values; stored and expired with the vault) of every real T-STR, P-ONE and T-EMAIL value of 4 or more characters ever seen in a structured field. Word sequences (1–4 words) in output strings are checked against it: a hit is tokenized in F fields and blocks the response in kept fields. This is the backstop for names, which match no pattern.
- **Free text (F).** A value is kept only if it fully matches a reviewed message template, for example an IWS error message with a typed slot for an account number. Templates are added by the CTO, never by agents and never copied from the catalog: the masked sample shows which F field needs one, and the CTO reads its text in a manual reproduction on the trusted machine (§8.4). Template slots are masked by their type; there is no untyped "keep" slot. Anything else is replaced as a whole by `Text-<8>`. `otherInfo`, tracker and email bodies, and `reason` are always tokenized.
- **Pattern detectors** (§8.1) then run over every template slot and every kept string. A match is tokenized by its detected type.
- **`spReference` and customer-entered descriptions** (account metadata, subscriber organization, vessel, resource group, tracker, pooling group, voucher order, PTT device) are tokenized as whole values (T-STR, reversible), because they may hold customer names or order numbers. Catalog and system descriptions (outages, call types, IMEI profiles, notifications) get F, so templates can keep the ones agents need.
- **Embedded XML** (`iwsLogImpl.request`/`response`, `baseQueueEntryImpl.request`/`response`) is unescaped, parsed with the same safe parser, masked with the field map of the operation it names, and re-escaped. It is masked only if its root element equals `requestedOperation` (or `operation`) and that operation is allowlisted; otherwise, or if it does not parse, the element is dropped (D). Auth fields inside it (`signature`, `callerPassword`) are dropped first.
- **CSV rows** (`reportResultDetailsEntryImpl.row`) need the report's column map (§13 #8). Until then the method is refused.

### 4.5 Unknown elements: fail closed

Every element and attribute path in every allowed method's request and response, keyed by (operation, `xsi:type`, path), is classified in a field map: one of the treatments above, or "keep". The generator reads the live WSDL (§7.2) and emits every path as **UNCLASSIFIED**. Only the reviewed override file assigns a treatment, `keep` included. The generator may propose `keep` for booleans, enumerations, dates and numeric quantities; each proposal is listed in the generated file for review and takes effect only once copied into the override file. It never proposes `keep` for `xsd:string` or ID-like integers: the CTO classifies those one by one (for example catalog names and plan IDs). CI fails on any UNCLASSIFIED path in an allowed method.

At runtime, an unknown path, an unknown `xsi:type`, any attribute other than `xsi:type`, `xsi:nil` and a plain `xml:lang` (§13 #27), or non-whitespace text outside a leaf element blocks the whole response (§8.4) until the CTO classifies it. The run manifest counts the elements the policy removes on purpose (§5.1). Strict mode is a code constant: there is no non-strict mode in S2. This mirrors the gateway rule that CI fails on an unclassified WSDL operation (Annex D §2.1).

### 4.6 Decision: keyed tokenization with a vault, not FF1

| | Keyed tokenization + vault (decided, §13 #2) | NIST FF1 format-preserving encryption with a protected key |
|---|---|---|
| Consistency | Deterministic derivation | Deterministic |
| Reverse mapping | Vault lookup | Decryption, no storage |
| Scope limit (§5.5) | Natural: only issued surrogates have a vault row, so a guessed surrogate in a plan maps to nothing | None: every string in the format decrypts to some real value, so a plan could enumerate surrogates and act on arbitrary real lines; scope needs a separate allowlist anyway |
| Recognizably non-real | Yes: room for a reserved prefix, because the vault, not the format, carries the information | Hard: a reversible mapping of n-digit strings onto n digits leaves no room for a reserved prefix plus a valid check digit |
| Leak detection | At runtime: any real-format value the masker did not place in this response. Offline (fixture scans, people reading output): anything outside the reserved prefixes | Offline scans and readers cannot tell a surrogate from a real value by format |
| Storage and state | A vault table (rows grow with the identifiers seen) | None |
| Library risk | HMAC and AES-GCM from the standard library and `cryptography` | Few maintained, audited Python FF1 implementations (*Inferred*; would need its own review) |

The vault costs a table and one lookup per identifier. Recognizable surrogates and the scope limit are worth that.

## 5. The recorder and recording plans

### 5.1 How a run works

The recorder is a command-line program (`python -m airtimesat_platform.recorder`, called `recorder` below) that only the CTO runs, only on the trusted machine (§6.5). It has no network listener and no unattended mode.

| Command | Where | What it does |
|---|---|---|
| `recorder check <plan>` | CI and anywhere; no secret, no vault | Strict YAML load, schema, allowlist, call limits, hard blocks, WSDL schema validation of every request, and the format of every identifier (a reserved-prefix surrogate, never a real-format value) |
| `recorder run <plan> [--dry-run] [--writes]` | Trusted machine | Runs the plan (steps below) |
| `recorder inventory add` | Trusted machine | Registers assigned test inventory (§5.6) |
| `recorder note` | Trusted machine | Records a CTO action taken outside the recorder, such as a DEACTIVE (§5.7), in the run log. It names the line by its surrogate only, and the note text passes the §8.1 detectors |
| `recorder incident clear <id>` | Trusted machine | Re-enables a method after a runtime block is fixed (§8.4) |
| `recorder backup` | Trusted machine | Writes an encrypted vault backup (§6.3) |
| `recorder keys init` | Trusted machine, once | Generates the masking keys for Keeper (§6.2) |

A live run:

1. **Reviewed plan only.** The recorder refuses a live run unless the working tree is clean and `HEAD` is a commit on `origin/main` (checked after a fetch). It records the commit SHA and the plan's canonical digest. A dry run may name a plan that is not merged yet, because it never contacts IWS, but the recorder itself still runs only from a clean checkout of `main`, because a dry run loads the masking keys and opens the vault. These checks live in the code being run, so they catch mistakes, not a malicious commit; the CTO's check of the merges on `main` before running a new commit is the control (§6.5).
2. **Keys and secret for this run only.** The Keeper CLI pipes the masking keys, and for a live run also the SITEST secret, to the recorder's standard input (§6.2). They are held as `SecretValue` objects in memory and are gone when the process exits. Core dumps and OS crash reports that capture memory are disabled for the process, and where the OS allows it the process is marked non-dumpable (on Linux, `PR_SET_DUMPABLE` 0), which also stops other processes of the same user from reading its memory.
3. **Checks.** `recorder check` runs again, plus the vault checks: every surrogate in the plan must be issued (§5.5).
4. **Calls, one at a time.** For each call in order, the recorder builds the request (resolving references to earlier masked responses, §5.2), unmasks it (§5.5), and calls `gateway.sitest_port`, which re-checks, signs and sends it to SITEST (§7.1). The raw response stays in memory. The masking engine masks it, the runtime detector checks the result (§8.4), and only then is the masked exchange written to the staging folder `tests/fixtures/masked/recordings/<plan-id>/<run-utc>/`. The request written is the plan's request with surrogates, never the unmasked or signed one.
5. **Fail closed.** On any block or failure, nothing is written for that call, an incident row is written (element path and detector id, never the value), the raw bytes are discarded and the run stops (§8.4).
6. **Before git.** At the end the recorder writes a manifest (plan id, commit SHA, plan digest, run time and, per call, the operation, decision, outcome code, IWS duration, elements dropped on purpose, surrogates issued and the in-prefix counter, §4.2), then runs `scripts/leak_scan.py` and gitleaks over the staging folder. While it still holds them, it also checks every staged file for the SITEST secret and each loaded key (raw, hex and Base64), which have no fixed format that gitleaks could recognize. Any hit deletes that run's staging folder, writes an incident and exits non-zero; otherwise it prints a summary. The CTO reads the masked output, commits it on a branch (the pre-commit hook scans again, §8.3) and opens a PR. CI runs the scans again over the PR range, and the CTO merges once CI is green (through the bypass, because GitHub does not let him approve his own PR; `docs/SETUP_CHECKLIST.md`, step 7).
7. **Backup.** The recorder prompts for `recorder backup` at the end of every live run (§6.3).

### 5.2 Recording plan format

A plan is a YAML file under `recording-plans/` in this repository, written by an agent (or the CTO), checked by `recorder check` in CI and reviewed by the CTO in a PR like code (§9.2). It is parsed with a strict loader: no duplicate keys, anchors, aliases, merge keys or tags; schema-validated; unknown keys refused. The CTO reviews the raw YAML and the recorder runs what the loader parses, so the two cannot differ.

```yaml
id: RP-2026-003
title: SBD account shapes for ST-03
purpose: Annex F ST-03, SBD account variants present in SITEST
expires_at: 2026-11-30T00:00:00Z        # a live run after this time is refused
max_calls: 12                            # never above the code constant (200, *Inferred*)
calls:
  - id: search
    endpoint: provisioning
    operation: accountSearch
    request: |
      <request>
        <filterType>IMEI</filterType>
        <filterValue>990000000318651</filterValue>
        <filterCond>EQUALS</filterCond>
        <limit>5</limit>
      </request>
  - id: account
    endpoint: provisioning
    operation: getSubscriberAccount
    for_each: ${search.accountNumber[0:3]}   # surrogates taken from the masked response of "search"
    request: |
      <request><accountNo>${item}</accountNo></request>
```

- A request is the body of the operation without authentication fields (`iwsUsername`, `signature`, `timestamp`, `serviceProviderAccountNumber`, `caller`, `callerPassword`); the signer core adds them (§7.1). This is the shape of the gateway's internal interface (Annex D §2.1; Annex F §6.2), so code agents write against recordings also works against the gateway later.
- Identifiers in a plan are surrogates from committed recordings, or references (`${call-id.field[...]}`) to surrogates in the masked responses of earlier calls in the same run. A reference resolves on the masked response and is then unmasked like any other surrogate, so the plan never names a real value. A reference may fill only an identifier field: every other value (enums such as `newStatus`, limits, dates, flags) is a literal in the plan, so `recorder check` and the CTO's review see what is sent.
- No real value appears anywhere in a plan: `scripts/leak_scan.py` scans `recording-plans/` in strict mode (§8.3).
- A plan that writes has a `writes` section (§5.6). Without it, a write operation fails `recorder check`.

### 5.3 Method allowlist

Default deny: a method not listed below is refused. The lists are code constants with tests, reviewed line by line; they are not configuration.

**Reads.** Drawn from the checklist v1.7 methods (Annex E §2.2) and the spike experiments (Annex E §1.4). A plan may use any read below; whether it needs SP-wide data (rather than test inventory and a few sample accounts) is part of the CTO's plan review. Every call is capped as listed, every plan by `max_calls` (at most 200), and every run by 500 distinct subscriber records (*Inferred*).

| Group | Methods | Limits |
|---|---|---|
| System | `authenticatedPing`, `getSystemStatus` (both endpoints), `getProjectVersion` (both), `findServiceProviderProfile`, `getDemoAndTrialCounts` | — |
| Catalog cascades | `getDemoAndTrialBundles`, `getPromoBundles`, `getSBDBundles`, `getM2MBundles`, `getVoiceBundles`, `getDataBundles`, `getVCSBundles`, `getDataSpeeds`, `getCommitmentPeriods`, `getLanguages`, `getLanguageChoices`, `getBundle`, `getServicePlans`, `getServicePlan`, `getSubmarkets`, `getModels`, `getModel`, `getManufacturers`, `getVerticals`, `getRudicsGroups`, `getAirlines`, `getFlagStates`, `getPrepaidPlans`, `getVoucherDenominations`, `getEvoucherInventory`, `getSecondaryDataServices`, `getBurstDeviceBundles`, `getBurstServiceBundles`, `getBurstSubscriptionNames`, `getBurstBroadcastCoverageAreas`, `getProgrammableButtons`, `getLocalNumberRegions`, `getVesselTypes` | `getEvoucherInventory`: `limit` 1–50 |
| Lines and devices | `accountSearch`, `getSubscriberAccount`, `validateDeviceString`, `getDevices`, `searchSimLock`, `getRechargeHistory`, `getPrepaidAccountDetail`, `getSubscriberOrganizations`, `getSubscriberOrgDetail`, `getVessels`, `getVessel`, `bulkActionSearch` | Every limit is a required inclusive range. `accountSearch`: `limit` 1–50, `startRow` ≤ 200 (*Inferred*), no `SMART` filter, `filterCond` `EQUALS` or absent, a filter required. `getDevices`: `numResults` 1–20 (0 means all to IWS). `getRechargeHistory`: `limit` 1–50. `getSubscriberOrganizations`: an issued `Id` only. `getVessels`: `id`, `imo`, `mmsi` or a full issued `Vessel-` surrogate, never a name prefix. `bulkActionSearch`: by `bulkRequestId` only, `Wildcard` absent or `FALSE`, no wildcard character. Search inputs follow §5.5 step 8 |
| Queue and IWS log | `getQueueEntries`, `getQueueEntry`, `getIwsRequests`, `getIwsRequest` | Window ≤ 24 h, `Limit` 1–100 (`getIwsRequests`; `getQueueEntries` has neither input in the catalog, #31). Only entries whose `caller` starts with `rec.` are kept; the rest are removed before masking and counted. The only filter is the caller prefix: `requestUser` is the same for recordings and the CTO's own calls (§13 #4). `getIwsRequest` and `getQueueEntry` refuse ids that no recording produced (the run log maps IWS request ids to calls, §5.8). `getQueueEntries.createdBy` is set by the recorder (§5.5 step 8). Embedded XML handling in §4.4 |
| Reporting metadata | `getReportTypes`, `getReportCategory`, `getReportColumns`, `getReportParameters`, `getReportPlanNames`, `getUsageUnits`, `getUsageCallTypes` | — |

A list response with more rows than the request allowed is blocked (§8.4). Names in these lists are catalog names. The code constants use the WSDL operation names (for example `getSubscriberOrgs`, `getEVoucherInventory`; Annex D §2.2), and a test asserts that every allowlisted and refused name exists in the WSDL snapshot.

`getAccountPoolingGroups` and `getAccountPoolingGroup` need `caller` plus `callerPassword` of a technical SPNet user (Phase 1 plan §1.3). The recorder holds no SPNet password, so they stay refused until the CTO decides otherwise.

**Writes, only in a plan with a `writes` section that the CTO runs with `--writes` (§5.6):** `activateSubscriber` (`bulkAction` `FALSE` or absent), `accountUpdate` (no status change; no change to `sim`, `imei`, `msisdn` or `ip`; §5.6), `setSubscriberAccountStatus` (to `SUSPENDED` or `ACTIVE` only; `bypassQuarantine` absent or `FALSE`), and, only for services sold, `rechargePrepaidAccount`, `subscribeBurstService`, `unsubscribeBurstService`. Device swaps wait for a CTO-confirmed class (§5.4, §13 #7).

### 5.4 Always refused

| What | Why |
|---|---|
| DEACTIVE in any form: `setSubscriberAccountStatus` with `newStatus` `DEACTIVE` or `CLOSED`; any `accountStatus` change through `accountUpdate` | DEACTIVE stays with the CTO (re-plan §3.4). `CLOSED` is terminal too (catalog `methods_provisioning.md`, `setSubscriberAccountStatus`); treated the same (§13 #6) |
| Beta and production | No such endpoint exists in the recorder's, the masker's or the signer core's code or configuration; the transport connects only to the pinned SITEST address and never asks DNS for it (§7.1) |
| Unknown methods, wrong case, body root not matching the path's endpoint, a SOAP 1.2 `action` in the plan that differs from the root element, authentication fields in the request | Default deny; the operation must equal the body's root element (Annex D §2.1). The signer core sets the outgoing action itself (§5.7) |
| SP-wide writes: `manageDestinations`, `sbdDestinationSearchReplace`, `sbdMOQueuePurge`, `updateEmailNotification` | The first three act on every matching contract (Phase 1 plan §4.6); `updateEmailNotification` acts at SP level (catalog), refused by design choice |
| Bulk: `bulkAccountUpdate`, `bulkAddPrepaid`, `bulkDeletePrepaid`, bulk `associateSimToImeiDevice`, bulk `deviceTransferOwner`; `activateSubscriber` with `bulkAction` `TRUE`, any `*BulkDetails` element, or a `BULK` literal in a device field (`ALWAYS_REFUSED_BULK`) | Cannot be scoped to test inventory; no bulk DEACTIVE (re-plan §8.1) |
| Destructive or inventory-moving: `deletePrepaidAccount`, `deactivateTelephonyScratchCard`, `unquarantineDevice`, `deviceTransferOwner`, `loadIMEI`, `restrictedSimSwap`, `associateSimToImeiDevice`, `disAssociateSimFromImeiDevice` | Irreversible or outside test scope |
| Not in S2: `accountUpdateDevices`, and any `accountUpdate` that changes `sim`, `imei`, `msisdn` or `ip` | A swapped-out device appears to go to `INACTIVE`, which needs Service Delivery to re-use, and released numbers and IPs go into quarantine (catalog `enums.md`; to confirm in ST-04). One swap can burn scarce inventory (§13 #7) |
| Credentials and users: `resetIWSUserPassword`, `resetUserPassword`, `userAuthenticate`, `findUserProfiles`, `createUserProfile`, `updateUserProfile`, `changeUserProfileStatus`, `unlockUser`, `getSPNetGroups`, `getSPNetPages`, `resetTelephonyVMPin` | Return or change secrets (Annex D §2.5, §2.8) |
| DIDWW: `addDIDWWNumberInventory`, `getDIDWWNumberInventory`, `removeDIDWWNumberInventory` | Need `callerPassword` and `didwwUserApiKey` |
| Money and vouchers: `orderScratchcards`, `activateScratchCards`, `activateTelephonyScratchCards`, `updateScratchCardStatus`, `refundPrepaidVoucher`, `getScratchcards`, `getScratchCardBatches`, `getScratchcardDeals`, `getScratchcardOrders`, `getScratchCardActivationStatus`, `searchVoucherOrder`, `getPrepaidAccountSummary`, `searchDeviceUsage` | Money writes, PINs in responses, or bulk personal data |
| Reports delivered outside the recorder or returning bulk rows: `createScheduledReport`, `updateScheduledReport`, `getScheduledReports`, `createOnDemandReport` (background mode always; inline mode in S2, §13 #8) | Background reports are emailed to the requester with real data (Phase 1 plan §4.6); scheduled reports carry delivery credentials (Annex D §6) |
| Report job metadata: `getReportTransactionLog`, `getFileList` | No recorder-created reports exist in S2, so they would only show other users' report activity (file and report names, parameters, error text, delivery addresses); revisit with §13 #8 |
| Raw usage: `getCertusRawUsage`, `getIOPRawUsage`, `getSBDRawUsageNew`, `getTelRawUsage`, `getSubscriberUsage` | CDRs with locations and called numbers; §13 #8 |
| Configuration writes on the reporting endpoint (trackers, profiles, resource groups, comm status), `updateTopicAssociation`, `updateQueueEntry`, vessel writes, secondary data service writes, organization writes | Not needed for S2–S3; they push emails and names into SITEST |

### 5.5 Requests that carry masked identifiers

1. The recorder validates each request in the plan against the WSDL schema (in `recorder check` and again at run time), then classifies every element with the field map (§4.5). Any element beyond its `maxOccurs`, mixed content, a comment, processing instruction, CDATA section or DTD, an unknown attribute, or an `xsi:type` outside the field map refuses the plan. An unknown element refuses it too. This closes parser differentials: the masker reads the first of two duplicate elements, while a Java binding on the IWS side may keep the last.
2. For each identifier field, the value must be a surrogate **the masker issued**: a vault row for `(type, surrogate)` must exist. The type comes from the field map or the typing enum (§3.2). If no row exists, the plan is refused with `IDENTIFIER_NOT_ISSUED` before any IWS call. A real-format value outside the reserved prefixes fails `recorder check`, because no agent should hold one.
3. The masker replaces each surrogate with the decrypted real value in memory and records the pair for known-value replacement on the way back (§4.4).
4. Free-text fields in the request are scanned by the detectors. A match refuses the plan: this stops a plan from writing a real identifier into SITEST, from where it could come back unmasked in another field.
5. **Reads.** Surrogates are global handles: any issued surrogate, from any committed recording, can be named in a later plan while its vault row exists. A surrogate whose vault row has expired (§6.4) never resolves again; a new recording issues a new surrogate for the value (§13 #30). That is what lets agents chain experiments (§9.1). Guessing works rarely (about 3% of guessed `SUB-` surrogates hit an issued row at 32,000 issued, *Inferred*), and the CTO's plan review and the plan and run caps bound what a lucky guess returns (§5.3, §8.5 #6).
6. **Writes** may use only surrogates that are both issued **and** in the plan's scope: the plan's test inventory, or accounts derived from it (§5.6).
7. Literal values a write needs must be real, non-personal values Globalsat controls (for example `spReference` `GS:TEST-001`) and must be listed in the plan's `writes.allowed_literals`. A literal never fills an identifier-typed field (a number, address, host or email): those come only from registered test inventory, so no plan can point a delivery destination or notification at a server or mailbox the CTO did not register. The CTO's test mailbox is registered inventory of type EMAIL, not a literal. Anything else that looks like an identifier is refused.
8. **Search inputs.** Every search input aimed at a masked field is identifier-typed and must be an exact issued surrogate; free text is never accepted in a search input, so partial-match searches cannot be used to rebuild a real name character by character. In a read, a free-text field must be empty, and an identifier filter that is present must not be blank or nil, which IWS may read as "all"; leaving the element out is how a plan sends no filter. Surrogates in wildcards (`*`, `%`) cannot be mapped, so wildcards on identifier filters are refused. `accountSearch.filterCond` must be `EQUALS` (absent means `EQUALS`): `CONTAINS`, `LIKE`, `NOT_EQUAL` and the other negations are refused. `getVessels` accepts only `id`, `imo`, `mmsi` or a full issued `Vessel-` surrogate. `getSubscriberOrganizations` accepts only an issued `Id`. `getQueueEntries.createdBy` is overwritten with the recorder's own value (its `caller` or the IWS username, whichever IWS records; uncertain until the first recording), so no plan names a real login.

### 5.6 Writes on test inventory

Writes run only when the CTO runs a plan with a `writes` section, with `--writes`, after a dry run. The controls are the lean form of the VM design's write guard: the plan-approval signatures and the signer's own write guard are not needed while the CTO runs every call on one machine, and are deferred to agent writes in Part 2 (§12.4).

```yaml
writes:
  max_writes: 6                           # budget for the whole plan, across runs
  inventory:                              # surrogates of test-inventory rows the CTO registered
    - {type: IMEI, surrogate: "990000000725905", service: SBD}
    - {type: EMAIL, surrogate: "u-q7m2x9k4@example.invalid", service: SBD}   # the CTO's test mailbox
  allowed_literals:                       # real, non-personal values Globalsat controls
    - {field: subscriberAccountMetadata.spReference, value: "GS:TEST-001"}
  methods:
    - {method: activateSubscriber, service_types: [SBD]}
    - {method: setSubscriberAccountStatus, new_status: [SUSPENDED, ACTIVE]}   # DEACTIVE and CLOSED are hard-blocked anyway
    - {method: accountUpdate, status_change: forbidden, mutable_fields: [subscriberAccountMetadata.spReference]}
```

A write plan's `expires_at` is at most 14 days after it merges.

**Test inventory registration.** Iridium's assigned test inventory (re-plan §11.1 Q10) is registered by the CTO with `recorder inventory add` on the trusted machine. The CTO types each value interactively, twice and without echo, from Iridium's assignment list, never as a command-line argument, which shell history or a process listing could keep. The tool writes the real value to the vault and a row to the test-inventory table (type, surrogate, service, and the HMAC of the real value under the inventory key, §6.2), and prints only the surrogate for the plan. Real inventory values never enter git, a plan file or an agent session.

**Enforcement, in order.**

1. The plan has a `writes` section, the run has `--writes`, and the CTO types the plan id at the prompt.
2. The plan is within its validity and its `max_writes` is not spent (counted in the local run log across runs).
3. The method is in the global write allowlist (§5.3) **and** in the plan, with its constraints (service type, allowed status values).
4. The hard blocks pass (§5.7).
5. Every identifier is issued **and** in scope (§5.5): a test-inventory row named in `inventory`, or a derived account of this plan. Derived accounts come only from the success field of an `activateSubscriber` response, after a read confirms that the account's device is the plan's test-inventory device. Writes address accounts by contract number only (`updateType` `SUBSCRIBER_ACCOUNT_NUMBER`, or `accountNo`). Before every write the recorder re-reads the target and refuses unless its devices are test inventory, because SITEST is refreshed from production and a number in scope yesterday can belong to a real contract today. Derived accounts expire with the plan and are cleared on a detected SITEST refresh (a `getProjectVersion` or `getSystemStatus` version change).
6. `accountUpdate`: the recorder reads the current account (`getSubscriberAccount`, required before `accountUpdate` anyway; Annex D D4) and diffs the planned object against that read. Fields with non-reversible treatments (P-ONE, C, G, D, F) must equal the masked value from the read and are restored to the real values from the read. Each changed field must be listed in `mutable_fields`; any other difference is refused. `accountStatus` always comes from the read, and `sim`, `imei`, `msisdn` and `ip` may not change (§5.4).
7. A dry run of the same plan digest was made within the last 24 hours. `--dry-run` runs every step except the send, and shows the **masked** final request and the verdict, without contacting IWS.
8. The recorder shows the masked final request and the last 4 digits of each real test-inventory value it addresses, and the CTO confirms with `y`. Then the send. No automatic retry on a write (Annex D §2.5).

**Idempotency.** The run log records every write step as sent, `ok`, an IWS fault code or `unknown`. A later run of the same plan never resends a write step that was already sent; the CTO writes a new plan instead. A timeout or an IWS system error on a write is recorded as `unknown`, and the agent proposes the probes of Annex D §2.5 (for example `accountSearch` after an activation), all reads, in the next plan.

### 5.7 The hard block on DEACTIVE

The block is code, not plan data, so no plan can lift it. It is checked in the recorder and again, by an independent implementation, in the signer core's guard (§7.1):

- `setSubscriberAccountStatus` with `newStatus` `DEACTIVE` or `CLOSED`, or with `bypassQuarantine` present with any value other than `FALSE`, is refused with `ALWAYS_REFUSED_DEACTIVE` before any other check. The comparison runs after NFKC normalization, trimming and case folding, so ` DEACTIVE `, `Deactive` or full-width text are caught.
- `accountUpdate` that would change `accountStatus` is refused (§5.6 step 6).
- `activateSubscriber` with `bulkAction` other than `FALSE` or absent, any `*BulkDetails` element, or a `BULK` literal in a device field is refused with `ALWAYS_REFUSED_BULK`.
- Every method in the always-refused list (§5.4) is refused, including bulk and destructive ones.
- The outgoing envelope is **rebuilt from scratch**, never edited from the plan's tree: no SOAP Header, exactly one Body child, enum values such as `newStatus` written from the signer core's own constants (`SUSPENDED`, `ACTIVE`), never the plan's bytes; Content-Type and action set by the transport. The check then runs again on the final bytes after unmasking and auth injection.
- No flag, option or plan field lifts it, for anyone, the CTO included.
- A plan that contains a blocked call fails `recorder check` in CI; a blocked call at run time stops the run with its refusal code on the CTO's terminal and in the run log. It is never silent.
- The block and its tests live in files on the mandatory review list (`recorder/policy/hard_blocks.py`, `gateway/sitest_guard.py`, `tests/masker/test_mask_hard_blocks.py`).

DEACTIVE in the spike's SBD lifecycle and in the final dry run stays a CTO action outside the recorder (re-plan §3.2; S5). The CTO's path (decided, §13 #6): a manual call from the trusted machine (SoapUI or the WSDL Explorer), never during a recording run, recorded afterwards with `recorder note` so the run log and the evidence index show it. The CTO takes the target only from Iridium's test-inventory assignment list and his own test plan, never from a recording plan, a runbook change he has not reviewed or an agent's message, and `recorder note` refuses a DEACTIVE note for a surrogate that is not registered test inventory. Each DEACTIVE of an SBD line releases its IMEI (Annex E §1.4), which frees test inventory for the next ST-04 run.

### 5.8 Calls, concurrency and the IWS log

- **One request at a time.** The recorder sends calls serially, and the signer core's transport is limited to 1 connection. So a run holds at most 1 of the IWS user's 2 concurrent request slots, and one slot is always free for the CTO's own call (catalog Rules; Annex D §2.4). "Too many connections!" stops the run. A call cut off by a timeout puts the next call into a 30–60 s cooldown, because IWS may still be working on it (Annex D §2.4, inferred there).
- **No permit ledger in S2.** With one CTO-run process there is nothing to coordinate. The gateway's Postgres permit ledger goes back to S3 with the gateway prototype (and into Part 2, §12.2).
- **`caller` marking.** The signer core sets `caller` to `rec.<plan-id>`. Certification runs use the gateway's `gs.<tenant>.<user>` form (Annex D §2.8). `getIwsRequests` returns `caller`, so an extract can be split by prefix; whether IWS records `caller` as sent is checked in the first recording (§10.2). The User Activity Report aggregates by IWS user and month and has no caller column (catalog `reports_library.md`), so it counts recording calls (§13 #22).
- **Quiet windows.** The CTO runs both the recordings and the dry runs and certification run, so no recording runs inside a certification window or a CTO dry run. This is a calendar rule, not code.
- **Clock.** The signer core compares each IWS response's `Date` header with the local clock and stops the run above 5 s of skew (*Inferred*). IWS signatures carry a UTC timestamp, and the skew IWS tolerates is unknown (Annex D open questions).
- **Run log.** A table in the vault database (§6.1), masked only: per call, the call id, UTC start and end, plan id, commit SHA, operation, endpoint, read or write, dry run, decision and refusal code, IWS duration, outcome (`ok`, an IWS fault code from `errorCodeEnum`, `unknown`), the `caller` sent, the signed UTC timestamp sent, the IWS request id if returned, and counts of dropped elements and detector hits. It maps IWS request ids to calls for `getIwsRequest` and `getQueueEntry` (§5.3).

## 6. The vault on the trusted machine

### 6.1 Storage

The vault is one SQLite file in the recorder user's data folder on the trusted machine, readable by that user only and outside every git working tree (`.gitignore` also excludes `*.sqlite` and `*.age`). It holds:

| Table | Content |
|---|---|
| Vault | `(type, surrogate, counter) → AES-256-GCM(real value)` under the vault key, with the type, surrogate and counter as associated data; first-seen and last-seen times; a tombstone flag (§4.3, §6.4) |
| Known values | The keyed-hash set of real name-like values seen in structured fields (§4.4) |
| Test inventory | Type, surrogate, service, HMAC of the real value under the inventory key (§5.6) |
| Derived accounts | Per plan, the contracts recorded from `activateSubscriber` successes on test inventory (§5.6) |
| Run log, incidents | §5.8, §8.4; masked only |

Real values appear in the file only as AES-GCM ciphertext under the vault key. Everything else is already masked or a keyed hash, so the file without the keys reveals no more than the surrogates already in git, and full-disk encryption covers the file as a whole. Value-level encryption uses `cryptography`, which the recorder needs anyway. Whole-file encryption with SQLCipher would need a native library build and its own licence review for no gain on the one sensitive column (*Inferred* choice). The recorder locks the file for the length of a run, so there is one writer.

### 6.2 Keys and the secret

| Key or secret | Form | Where it lives | Purpose |
|---|---|---|---|
| `K_mask` | 256-bit random | One Keeper record ("masker keys"), plus the offline escrow | Surrogate derivation (§4.3) |
| Vault key | 256-bit random | Same record and escrow | Encrypts vault values (§6.1) |
| Known-value hash key | 256-bit random | Same record | Cross-call known values (§4.4) |
| Inventory key | 256-bit random | Same record | HMAC of real test-inventory values (§5.6) |
| Backup key | age X25519 | Private key in Keeper and the offline escrow; the public recipient in the recorder's configuration | Encrypts vault backups (§6.3) |
| SITEST secret | `iwsUsername`, the secret key and the SP account number(s) | A separate Keeper record | Loaded only for a live run |

- **Generation.** `recorder keys init` generates the four 256-bit keys once and writes them to standard output for the Keeper CLI to store, never to a file. It refuses to run when standard output is a terminal, so the keys cannot end up in scrollback.
- **Loading.** For each run, the Keeper CLI pipes the needed records to the recorder's standard input, where `common/secrets_stdin.py` reads them into `SecretValue` objects (§7.2). Never as a command-line argument, an environment variable or a file. A dry run loads the masking keys but not the SITEST secret. Error messages name a secret, never its value (existing `SecretNotAvailableError`).
- **The SITEST secret** never reaches an agent session, a document, a log, git, a cloud service other than Keeper, or any machine other than through Keeper. Keeper syncs its records to every device where the CTO's Keeper is unlocked, so §6.5 limits where the masker-keys and SITEST records may be unlocked. There is no Beta copy anywhere: the same credential works on Beta, so a second copy would add nothing but exposure.
- **Rotation.** `K_mask` is not rotated in normal operation, because rotation changes every surrogate and makes every committed recording stale. After a suspected compromise of the vault or `K_mask`, the CTO generates new keys and the recordings are taken again. The SITEST secret is rotated by Iridium on request (procedure and lead time still to be obtained; re-plan §11.1 Q4), never by agents (`resetIWSUserPassword` is always refused, §5.4). A SITEST secret leak is also a Beta leak, so the CTO treats it like a Sev1 (re-plan §8.1).

### 6.3 Backup and recovery

- **Backup.** After every live run (the recorder prompts) the CTO runs `recorder backup`. It takes a consistent snapshot with SQLite's online backup interface, streams it through age to the backup recipient with no plaintext temporary file, and writes `vault-<UTC>.sqlite.age` to the off-machine target: a Keeper file attachment, ciphertext only (CTO decision, 20 Oct 2026; §13 #20). Backups are kept 30 days (*Inferred*).
- **What a backup exposes.** Real values in it are encrypted twice: by the vault key inside the file and by age outside it. Neither key is stored with the backup.
- **Custody.** The backup key, `K_mask` and the vault key are escrowed offline (a sealed copy with a named custodian, or a Keeper break-glass record), so a future deputy can recover if the CTO loses Keeper access.
- **Recovery.** A restore is tested once at the S2 exit: decrypt onto the trusted machine and open with the keys from Keeper. If the vault and its backups were lost, committed recordings would stay usable by agents, but their surrogates could not be named in new plans until the same values were seen again (deterministic derivation recreates them with the same `K_mask`, except where a collision counter differs). If `K_mask` were lost too, every recording would be taken again.

### 6.4 Retention

Working periods (§13 #15); Legal sets the final periods per country (re-plan §5 item 5):

- Vault values are deleted 90 days after last use, but `(type, surrogate, counter)` stays reserved forever as a tombstone: a reserved slot is never issued to another value, so an old surrogate in a recording can never come to mean a different person. Test-inventory rows, and rows named by a plan still within its validity, never expire.
- The run log is kept 18 months, like the gateway's technical log (Annex D §2.8). Backups are kept 30 days, so a deleted vault value is gone from every copy within about 120 days.
- Masked recordings in git are kept as long as the repository. They are pseudonymized personal data while the vault holds their values. A value seen again after its row was deleted gets a new surrogate, because the tombstone keeps the old slot reserved (§4.3, §13 #30). Deleting vault rows still does not anonymize old recordings: `K_mask` still exists, so anyone who holds it and guesses a real value can derive its old surrogate again (surrogate epochs are not in S2). Agent transcripts that read recordings are pseudonymized data held by the agent provider. Legal confirms the basis for both (§13 #21).
- No unmasked SITEST data reaches a hosting provider in Part 1 (GitHub and the agent provider hold masked data only, #21), so Legal's review of DigitalOcean is not needed for S2 (§13 #17).

### 6.5 The trusted machine

The trusted machine is the one CTO device that runs the recorder and holds raw data, the vault and key material. The CTO also makes manual IWS calls from it (the WSDL harvest, DEACTIVE):

- **One named device** ([FILL: which device]) with full-disk encryption that also covers swap and hibernation, automatic OS updates and a screen lock.
- **AI tools on the same user (CTO decision, 20 Oct 2026; risk accepted).** The trusted machine is the CTO's laptop, under the CTO's normal OS user, where AI tools may also run. Accepted residual risk: while Keeper is unlocked for a recording run, an AI tool or a malicious dependency running as the same user could read the masking keys, the vault key and the SITEST secret, and could see raw responses in memory or the last 4 digits the recorder shows (§5.6). What still holds: Keeper is unlocked only for the run and locked right after; no AI tool runs in the terminal session of a recording, and AI features of the terminal, editor, browser or OS that send screen, terminal or clipboard content to a cloud service are off during the run; clipboard sync to other devices is off; the recorder runs only merged commits on `main`; and no code from an unmerged branch is ever run on this laptop (no `make`, tests, `uv sync` or hooks from a PR branch).
- **Keeper.** The masking-keys and SITEST records stay in the CTO's normal Keeper; there is no separate identity (CTO decision, 20 Oct 2026). Keeper syncs, so they can be unlocked on any device where the CTO's Keeper is: lock Keeper when not recording, and keep no persistent Keeper CLI login.
- **Only reviewed code runs here.** The recorder, `uv sync`, `make`, tests and hooks run under the recorder user only from a clean checkout of a commit on `main`. Unmerged branches are reviewed on GitHub and tested in CI, never run here, because any code run as this user can read the vault, the keys while loaded and Keeper while unlocked. `main` is trusted only as far as only the CTO merges into it, and agent sessions currently reach GitHub as the CTO's account, which holds the merge bypass (`docs/SETUP_CHECKLIST.md`, step 7b, Limit). So before syncing or running a new `main` commit, the CTO lists the merges since the last commit he ran (`git log --first-parent <last-run-sha>..origin/main`) and confirms that each is a PR he reviewed and merged. The check uses git, not the recorder, because a malicious recorder change could hide itself from its own check (§13 #19).
- **No cloud sync or online backup.** The recorder user's home folder (the vault, the run log, the git checkout with its staging folder, the Keeper CLI configuration and any manual-call files) is excluded from cloud sync and online backup. Only the encrypted `recorder backup` leaves the machine (§6.3), and masked recordings leave only by the reviewed PR (§5.1).
- **Manual calls.** The WSDL harvest, `authenticatedPing`, DEACTIVE and raw reproductions (§8.4) leave raw data on screen and in tool files. The CTO keeps the secret out of saved SoapUI projects, clears SoapUI's request and response history after each session, uses a private browser window for the WSDL Explorer, keeps any raw file (and its editor swap and backup copies) in one folder outside every git working tree, and never pastes raw output into an agent chat, an issue or a PR.
- **A minimal environment.** The recorder is installed from the reviewed commit in its own venv with `uv sync --frozen`, so every dependency is pinned and hash-checked.
- **Software keys in Keeper, no hardware key** (CTO decision, 20 Oct 2026; §13 #14). Each key and the secret are loaded only for a run (§6.2). The residual risk, a compromised machine or Keeper session, is stated in §2.2 and accepted.
- **Raw data stays here.** The raw ST-03 sample, if the CTO takes one (§9.3), is kept on this machine only, in the manual-call folder, and deleted once ST-03 is judged.

## 7. The signer core and its place in the code

### 7.1 Signer core and Beta unreachability

| Option | What it means | For | Against |
|---|---|---|---|
| 1. A minimal signer inside the recorder | The recorder has its own HMAC signer, envelope builder and HTTP client | Fastest start | Two signers to review and keep in step; breaks "gateway is the only code that talks to IWS" (`CLAUDE.md`); S3 rebuilds the same code |
| **2. S2 builds the gateway's SITEST signer core; the recorder calls it in process through `gateway.sitest_port`** (accepted, §13 #3) | S2 writes the first gateway modules: signing, envelope rebuild, the SITEST endpoint constants, an HTTP transport with a connection limit, and a guard | One signer, reviewed once; the "only the gateway talks to IWS" rule stays true; S3 starts with signing done and ST-02's offline vectors written (re-plan §10 puts them in week 5) | S2 grows by the signer review (§11.1); a contract change is needed (§7.3) |
| 3. The CTO makes every live call by hand | SoapUI or the WSDL Explorer | No code | Raw responses on screen, no masking at the source, no plans to review. Kept only for the WSDL harvest and DEACTIVE (§10.2) |

The signer core is small: UTC timestamp, HMAC-SHA1 over the operation name plus the timestamp, Base64 (Phase 1 plan §1.3; Annex D §2.3). D1 is not closed yet: if fallback A replaces the gateway with a plain-Java service (Annex F §6.3), the recorder either keeps the Python signer core as its SITEST client (a second signer, which needs a `CLAUDE.md` change) or calls the gateway service over the Annex D §2.1 interface; decided at G1.

**`gateway.sitest_port`.** A protocol, `SitestPort`, with one call (endpoint, operation, request, `caller`) that returns the raw response bytes, the signed timestamp and the IWS duration, and an in-process implementation that holds the `SecretValue`. For each call it runs the guard (the operation allowlist and the DEACTIVE and bulk blocks, a second implementation independent of the recorder's, §5.7), rebuilds the envelope from scratch and injects the authentication fields, signs, sends through the transport, replaces any echo of the signature in the response with `REDACTED` and never returns the signature. It also gives the recorder `iwsUsername` and the SP account numbers, which are identifiers to mask (§4.4), and loads the generated field map for the masking engine. In Part 2 the same protocol gets a second implementation, an HTTP client of a signer container (§12.2).

**Beta unreachable although the credential works there.** There is one IWS test user, and its credential works on SITEST and Beta (CTO decisions, 20 Oct 2026). The code alone must make Beta unreachable, in layers:

1. **No Beta in the code.** The only IWS endpoints the signer core can load are the two SITEST constants and the pinned SITEST address in `gateway/endpoints_sitest.py`: `iwstraining.iridium.com:8443`, paths `/iws-current/iws` (provisioning) and `/iwsReport-current/iws-report` (reporting) (catalog Rules; Annex D §1). Annex D's diagram also says "8843 to be confirmed"; the catalog says 8443. There is no setting, environment variable, flag or plan field that changes the destination. A test fails if any `iridium.com` host name other than `iwstraining.iridium.com` appears anywhere under `src/` (from S4, except in `gateway/endpoints_production.py`, which the `sitest-only` contract keeps out of the recorder's reach, §7.3), so the test itself names no Beta or production host. Those names appear only in the CTO's manual check in a runbook under `docs/runbooks/`.
2. **Pinned host and address in the transport.** The transport connects only to the reviewed SITEST address, sends SNI and `Host` for `iwstraining.iridium.com`, verifies the TLS certificate for that name, follows no redirects, and checks before each send that the URL host equals the SITEST constant. It never asks DNS for the IWS address. If Iridium moves SITEST, calls fail until the CTO reviews and pins the new address; that is the intended failure. Any change to the pinned address is checked against the runbook's record of SITEST's and Beta's addresses before it merges, because with a certificate shared by both names a Beta address would pass the TLS check. The first live step records whether SITEST and Beta share addresses or a wildcard certificate (§10.2); if they do, the SNI and `Host` constant and the certificate check are the separation.
3. **The secret only in the recorder process.** It is loaded from Keeper for a live run and held only in memory (§6.2). Agents never have it, and no agent-reachable code or configuration names Beta.
4. **Review.** Every layer sits on the mandatory review list.

On the trusted machine DNS works and no firewall restricts egress. The container, DNS and firewall layers of the VM design return with Part 2 (§12.3).

### 7.2 Package plan

```text
src/airtimesat_platform/
  common/
    secrets_stdin.py            # StdinSecretsProvider: reads named secrets once from standard input (piped by the
                                #   Keeper CLI) into SecretValue objects; no file, no environment variable, no AWS
  gateway/                      # S2 builds the SITEST signer core; S3 grows it
    api.py                      # the console's public port (unchanged)
    sitest_port.py              # SitestPort protocol and its in-process implementation; field-map loader;
                                #   the recorder's only entry point into the gateway
    signing.py                  # HMAC-SHA1 signature, UTC timestamp, operation from root element
    envelope.py                 # rebuild the outgoing envelope; auth fields and caller first in <request>
    endpoints_sitest.py         # the two SITEST URLs and the pinned SITEST address as constants; nothing else
    transport.py                # aiohttp client: connector limit 1, no redirects, pinned address, TLS name check
    sitest_guard.py             # independent re-check on the final bytes: operation allowlist, DEACTIVE and bulk
                                #   blocks; redacts any echo of the signature
    wsdl/                       # WSDL snapshot (moved forward from S3; §13 #9)
      fieldmap/                 # generated paths, all UNCLASSIFIED, plus keep proposals (§4.5)
  masker/                       # the masking engine: pure functions over XML, a field map and a vault store
    engine.py                   # mask a response, unmask a request (§4, §5.5)
    fieldmap/overrides.yaml     # reviewed classifications: the only place a treatment is assigned
    tokenize/                   # surrogates.py (derivation, prefixes, check digits), vault.py (issue, resolve,
                                #   collisions, over a store interface)
    xmlsafe.py                  # lxml parser settings, embedded XML, serialization
    detect/                     # patterns.py (§8.1), scan.py (runtime detector, known values)
    logsafe.py                  # allowlisted structured logging and the detector filter (§8.4)
  recorder/                     # CTO-only CLI on the trusted machine
    __main__.py                 # check, run, inventory add, note, incident clear, backup, keys init
    plan.py                     # strict YAML loader, schema, canonical digest, ${...} references
    policy/                     # allowlist.py (reads and writes with limits), hard_blocks.py, writes.py (§5.6)
    store.py                    # the SQLite vault store, run log, test inventory, incidents (§6.1)
    output.py                   # masked exchange files and the manifest (§5.1)
recording-plans/                # reviewed recording plans (§5.2)
tests/
  masker/test_mask_*.py         # unit, shape and red-team tests
  leak/test_leak_*.py           # deny-list, log, no-raw-on-disk and fixture-scan tests
  recorder/test_recorder_*.py   # plan loader, run refusals, write checks
  gateway/test_signing.py       # offline signature vectors (ST-02)
  gateway/test_sitest_*.py      # guard, pinned address, no Beta host, no signature in results
  fixtures/masked/recordings/   # committed masked recordings
scripts/leak_scan.py
```

The recorder ships in four code PRs, each small enough to explain line by line: D1 (recording plans and `recorder check`), D2 (`recorder run` for reads, the vault store, the run log, the output files and manifest, `keys init`, `backup` and `incident clear`, process hardening, the caller keep and the `getIwsRequests` caller filter), D3 (writes, `inventory add` and `note`), and W, after the WSDL harvest (the snapshot, the field-map generator, the generated map and WSDL schema validation in `recorder check`).

The masking engine imports no gateway code and does no network I/O: the recorder loads the generated field map through `gateway.sitest_port` and hands it to the engine with a vault store. The generated field map stays under `gateway/wsdl/`, because `CLAUDE.md` keeps WSDL-derived files under `gateway/`. The guard in `gateway/sitest_guard.py` is a second, deliberately independent implementation of the block on DEACTIVE and bulk calls, so a recorder bug alone cannot send one.

### 7.3 Import-linter, CODEOWNERS and `CLAUDE.md` changes

| Change | Why |
|---|---|
| `masker-isolated`: unchanged (the masker imports only `common`), with `airtimesat_platform.recorder` added to its forbidden modules | The engine stays pure; the recorder depends on it, never the reverse |
| `soap-libraries-gateway-only`: remove `masker` from its sources (its comment already expects this). New `masker-no-transport`: the masker forbids `aiohttp` and `xsdata`, with `allow_indirect_imports = false` | The masker needs `lxml` to mask; HTTP stays in the gateway. Indirect checking works because the masker imports no app code that could pull HTTP in |
| New `recorder-boundary` (forbidden): source `airtimesat_platform.recorder`; forbidden `gateway`, `console`, `domain`, `archive`; `ignore_imports` = `recorder -> gateway.sitest_port` and `recorder.** -> gateway.sitest_port`; `allow_indirect_imports = true`, like `console-boundary` | The recorder reaches IWS only through the SITEST port |
| New `recorder-no-soap-libraries`: the recorder imports `aiohttp`, `xsdata` and `lxml` only indirectly (`allow_indirect_imports = true`) | XML parsing stays in the masker, HTTP in the gateway |
| New `sitest-only` (forbidden, `allow_indirect_imports = false`): sources `recorder`, `masker` and `gateway.sitest_port`; forbidden `gateway.api` and `gateway.endpoints_production`. A test pins the S4 production-endpoint module name, because import-linter skips forbidden modules that are not yet in the graph and would otherwise pass vacuously | A Beta or production endpoint in agent-reachable code is a defect (`CLAUDE.md`). `gateway.api` is the console's port and will reach production endpoints in S4 |
| New `gateway-one-way`: the gateway imports neither `masker` nor `recorder`. New `ports-apart`: `gateway.api` never imports `gateway.sitest_port` | Keeps dependencies one way and the two ports apart |
| `console-boundary`, `domain-pure`, `archive-isolated`: add `airtimesat_platform.recorder` to their forbidden modules | No app package reaches the recorder |
| `tests/test_import_contracts.py`: update `EXPECTED`; replace `test_other_contracts_ignore_no_imports` with an explicit allow-list (`console-boundary`, `recorder-boundary`); add `test_recorder_may_only_skip_the_sitest_port` | The test pins the contracts and fails today on any `ignore_imports` outside `console-boundary` |
| `CLAUDE.md` "Module boundaries": "`masker` imports only `common`; it may import `lxml`. `recorder` imports only `common`, `masker` and `gateway.sitest_port`, and runs only on the CTO's trusted machine." | The written rule must match the contracts |
| `CLAUDE.md` "Live-system boundary": replace "SITEST, through the masker, is the only IWS environment agents reach" and "Reach SITEST only through the recorder and masker" with: "Agents never call SITEST. In S2 the only SITEST client is the recorder, which the CTO runs on the trusted machine from a reviewed recording plan. Agents ask for live data by writing a recording plan in a PR." Also replace "Read calls through the masker are fine. Writes go only to assigned test inventory, inside a test plan the CTO approved." with "Recording plans may read within the recorder's allowlist. Writes go only to assigned test inventory, inside a recording plan the CTO approved and runs.", and "The masker and any agent-facing tool call the SITEST endpoint only" with "The recorder, and any later agent-facing tool, call the SITEST endpoint only" | Under option C no agent reaches SITEST, and no sentence may still say that one does |
| `CLAUDE.md` "Live-system boundary": replace "Only the gateway role (and, for SITEST only, the masker) reads an IWS secret, from Secrets Manager" with: "Only gateway code reads an IWS secret. In S2 the SITEST secret is read by the gateway signer core inside the recorder, from the CTO's Keeper, for a live run only. From S4 the production gateway reads IWS secrets from Secrets Manager." | The S2 secret no longer lives in Secrets Manager (this changes the arrangement agreed on 20 Oct 2026 for the masker) |
| CODEOWNERS: add `/src/airtimesat_platform/recorder/`, `/tests/recorder/`, `/recording-plans/` and `/docs/runbooks/` to the CTO's line-by-line list | The recorder writes to IWS, every plan is a live-call request, and the runbooks steer the CTO's manual calls (DEACTIVE, the Beta-name check) |
| CI: a `recorder check` job on every PR that touches `recording-plans/`, with no secret and no vault. It runs the checker from the base branch (`main`) against the PR's plan files, so a PR cannot change the checker that judges it; a PR that changes a plan targets `main` and touches nothing else. Every changed plan is judged, a type change included, and `recording-plans/` is a directory of regular files only (no symlink or submodule, for the directory itself too). A PR runs its own copy of the workflow, so the job itself is protected by Code Owner review of `.github/` and by the bot having no Workflows permission; a PR that changes both a plan and a workflow is never approved. `scripts/leak_scan.py` in `make security` and the pre-commit hook. `.gitignore`: `*.sqlite`, `*.age`, Keeper exports, and a narrow `!/tests/fixtures/masked/recordings/` exception, because the existing `recordings/` rule (raw captures) would otherwise ignore the masked recordings | Plans are checked before review; no vault, backup or key file reaches git; masked recordings can be committed while raw captures stay ignored everywhere else |
| `pyproject.toml`: add `aiohttp`, `lxml`, `cryptography` and `pyyaml` (wrapped in the strict loader, §5.2) as runtime dependencies; `hypothesis` and `lxml-stubs` (unless the pinned `lxml` ships types) for development. No `boto3`, `asyncpg` or new web framework in Part 1 | Licence gate and pip-audit cover them; any licence exception needs a written reason |

All of these files are on the mandatory review list. They change in the S2 code PRs, not in this design.

## 8. Leak tests and fail-closed

### 8.1 Detectors

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
| Long digit runs | 9 or more consecutive digits in every string element, except placed surrogates and the operational fields of §8.4 | catch-all |
| Known values | Match of any real value seen in this call, including the injected auth values (§4.4), compared after NFKC and case folding, because IWS may echo a value in another case | — |
| Cross-call known values | Keyed-hash match of output word sequences against every real name-like value seen (§4.4) | — |
| Signatures | Any Base64 string of HMAC-SHA1 length (27–28 characters, `=` padding) anywhere in output | Catalog signature algorithm; length rule *Inferred* |
| Sensitive names | Elements named like the secrets in §3.1 with a non-`REDACTED` value | Annex D §2.8 |

**Exemption.** A value is exempt only if it is byte-equal to a surrogate the masker placed in this response (a per-response set). A value that merely looks like a surrogate, but that the masker did not place, is a hit. Offline scans, which have no such set, use the reserved prefixes (§8.3).

Detectors also run after Unicode normalization (NFKC) and base64 decoding of long base64-looking strings. Separator removal is limited to digit groups joined only by spaces, hyphens or dots that total 12–20 digits, and it skips ISO-8601 and `DD-MON-YYYY HH24:MI:SS` timestamps. So `9 9 0…`, full-width digits or encoded copies do not slip past, while timestamps and version strings do not trip a rule. Detectors use linear-time regular expressions (RE2 or bounded patterns), so no input can make them backtrack for long.

### 8.2 Per-response-shape tests from synthetic data

- For every allowed method, a test builds a synthetic response from the WSDL schema (every optional element present, arrays of 1 and 3, each account subtype by `xsi:type`, nil and empty variants) and fills every identifier field with **canary** values: real-format values from a documented canary range that is not a surrogate prefix, so the detectors fire on them. The test asserts that the masked output contains no canary, no detector hit, every secret `REDACTED` (or nil or absent, §4.1), the same element structure, and that it validates against the WSDL schema.
- A **log leak test** drives every error path with canary data and asserts that no canary reaches the recorder's terminal output or run log (§8.4).
- The same for requests: every allowed write with surrogates maps back to the canaries, and every refused case is refused.
- A **deny-list test** on every response shape: the list of secret element names and the real-format patterns must never appear in output.
- Property-based tests (Hypothesis) for the detectors, tokenization round trips, collision handling and check digits.
- File names contain `mask` or `leak` (`tests/masker/test_mask_*.py`, `tests/leak/test_leak_*.py`), so CODEOWNERS routes them to the CTO.

### 8.3 Scanning before git

- `scripts/leak_scan.py` runs every detector of §8.1 over all text files in the repository, in strict mode under `tests/fixtures/` and `recording-plans/`. It allows reserved-prefix surrogates, and the canary range only under `tests/leak/` and `tests/masker/`; the in-prefix counter (§4.2) also confirms that the canary range is absent from SITEST. In CI it scans every commit in the PR range, not just the working tree, so a value added and removed inside a PR is still caught. It refuses non-UTF-8, binary or compressed files under `tests/fixtures/` and `recording-plans/`. It reports the file, line and detector id, never the matched value, because CI logs are stored at GitHub. It runs in the recorder at the end of every run (§5.1), in the pre-commit hook and in `make security` (and so in CI).
- **The last barrier is local.** CI runs after a push, so a CI hit means the data has already reached GitHub: that is a Sev1 (history rewrite and a GitHub request to purge cached views). The pre-commit hook is optional elsewhere, but it is installed on the trusted machine (§10.2 step 2), and the recorder's own end-of-run scan does not depend on it.
- gitleaks keeps scanning for secrets (`make security`, CI history scan), including its age secret-key rule. Its regex rules cannot check Luhn digits, so identifier detection lives in `leak_scan.py`.
- Adding the script and the Makefile and pre-commit targets changes gate configuration, which is on the mandatory review list.

### 8.4 Runtime detector: block and stop

After masking and before writing anything, the recorder runs the detectors over the masked response, including decoded embedded payloads. Detection is field-aware. Type detectors run on every element whose field-map class is an identifier treatment, F, N or unknown, and on every kept string element. Kept elements with an XSD numeric, date or boolean type, and kept elements listed in `overrides.yaml` as a version, size, count or operational ID (for example `iwsVersion`, `wsdlRevision`, project version fields, `cdrId`, `sessionId`, `requestId`, `transactionId`, `bulkRequestId`, `queueEntryId`), skip the IPv4, MMSI, IMSI and long-run rules; they are still checked against known values. Otherwise a version such as `22.2.0.1` (Annex E §1.4) would trip the IPv4 rule and disable `getSystemStatus`.

**Fail closed on every failure, not just on hits.** A masked exchange is written only when every stage returns an explicit clean result. Any exception, a masking-budget timeout (2 s, *Inferred*), an unavailable vault or key, a failed vault write, a non-SOAP body (such as an HTML error page), a response over 5 MB (*Inferred*), or a list with more rows than the request allowed writes nothing for that call and stops the run.

On any hit, or on an unknown element:

1. Nothing is written for that call, the raw bytes are discarded, and the run stops. The CTO sees `MASKING_BLOCKED`, the call id and the detector id.
2. An incident row is written with the element path and detector id, never the value.
3. The method is refused in later runs until the CTO clears the incident (`recorder incident clear`) after the fix, such as a new override or template, is merged.

**Logging.** The recorder's terminal output and run log carry an allowlisted field set only: call id, codes, timings, counts. A logging filter runs the §8.1 detectors and the known-value sets on every record; on a hit it drops the record and stops the run. Every exception, including an uncaught one (a top-level handler replaces Python's default traceback printer), is reported as type and code only, with no message and no local variables, because lxml, aiohttp and validation errors can echo input, and a traceback is what the CTO would paste into an agent chat to debug. There is no debug mode.

Nothing raw is kept for debugging, and no flag disables masking. If the CTO needs a raw response, the reproduction happens by hand on the trusted machine, outside the recorder (SoapUI or the WSDL Explorer); the fix is then verified through the recorder.

### 8.5 Red-team cases (part of the S2 test suite)

1. IWS error text that echoes a request value (`accountSearch` with a wrong filter type; `setSubscriberAccountStatus` on a missing account).
2. Escaped XML in `getIwsRequests` and `getQueueEntry` that contains other callers' requests, including `signature` and `callerPassword`.
3. Every account subtype through `getSubscriberAccount`, with identifiers in subtype-only fields (Certus voice lines, OpenPort phone lines, Paging `isdna`, vessel links).
4. Identifier variants: leading zeros, spaces, hyphens, `+` and `00` prefixes, IMEISV (16 digits), 14-digit IMEI without check digit, an SBD IMEI ending in 0 with an invalid Luhn digit, 20-digit ICCID, a real 12-digit number starting `99`, IPv6, mixed-case emails, full-width digits, values split across elements.
5. Free text and names containing identifiers and prompt-injection text; a name seen in a structured field in an earlier call, echoed in free text.
6. Enumeration: a plan full of guessed surrogates in the reserved prefixes fails `IDENTIFIER_NOT_ISSUED` before any IWS call.
7. A plan that tries to write a real-format identifier into `spReference` or `description`.
8. Operation-name and parser tricks: wrong case, a root element that differs from the endpoint, two operations in one body, auth fields in the request, a `caller` in the plan, duplicate `newStatus` or `accountNo` elements, a comment-split enum (`DE<!---->ACTIVE`), ` DEACTIVE `, `Deactive`, full-width text, SOAP headers, `xsi:type` substitution.
9. Endpoint tricks: Beta or production host names in plan fields or XML; redirects from the IWS side (never followed).
10. XML attacks: external entities, entity expansion, huge documents, deep nesting (parser with entity resolution and network access off and size and depth limits).
11. DEACTIVE through every path: `newStatus` DEACTIVE or CLOSED, `accountStatus` in `accountUpdate`, `bypassQuarantine` with any value but `FALSE` (`FALSE` is accepted), a plan that lists DEACTIVE (fails `recorder check`), bulk methods, `activateSubscriber` with `bulkAction` `TRUE`, a `*BulkDetails` element or a `BULK` device value, each also sent straight to `gateway.sitest_port`, which refuses it on its own.
12. Plan tricks: duplicate keys, anchors, unknown keys; a live run from a dirty tree or a commit not on `main`; an expired plan; a write call in a plan without a `writes` section; a write run without `--writes` or without a dry run of the same digest; a write over `max_writes`; a repeated write step; a `${...}` reference in an enum, status or limit field; an `allowed_literals` entry for an identifier-typed field; a DEACTIVE `recorder note` for a surrogate that is not test inventory.
13. Concurrency: the transport never opens more than one connection to SITEST.
14. `background=TRUE` on `createOnDemandReport` and every other always-refused method.
15. No false blocks: `getSystemStatus` and `getProjectVersion` with versions such as `22.2.0.1`, a kept 9-digit count, and a `statusDescription` holding a space-separated timestamp are not blocked.
16. Search oracles: prefix walking on `getVessels.vesselName`, `NOT_EQUAL` and `CONTAINS` on `accountSearch`, a name search on `getSubscriberOrganizations`, login guessing on `getQueueEntries.createdBy`: all refused or overwritten.
17. Fail closed: an exception inside masking, a masking timeout, the vault or a key unavailable, a failed vault write, an HTML error page from IWS, an oversized response, and a list with more rows than requested all write nothing and stop the run.
18. Bulk pulls: `numResults` 0, `limit` 0, a blank `getSubscriberOrganizations` `Id`, `startRow` beyond the cap, an unfiltered `accountSearch`: all refused; the per-run record cap holds.
19. A signature-length Base64 string in fault text, and an `iwsLogImpl` entry from another caller, never reach a recording.
20. Write scope after a simulated SITEST refresh: a derived account whose device is no longer test inventory is refused; an `accountUpdate` that changes a field not in `mutable_fields`, or writes `REDACTED` back, is refused.
21. No raw data on disk: a run against a synthetic transport that returns canary values leaves no canary in the staging folder, the vault file (except as ciphertext), the run log or the terminal log, including after an uncaught exception, and core dumps are off.

## 9. How agents receive recordings and request new ones

### 9.1 Recordings and the simulator

- **Where.** Masked recordings live under `tests/fixtures/masked/recordings/<plan-id>/<run-utc>/`, one masked request and response per call plus the manifest. The path matches `**/*mask*` in CODEOWNERS. Agents read them in any session: no special cloud environment, no token and no network allowlist entry are needed.
- **Consistent surrogates.** Recordings carry vault surrogates, consistent across runs, so an account seen in one recording has the same surrogate in the next, and agents can name it in a new plan. A surrogate whose vault row has expired (§6.4) never resolves again; a new recording issues a new surrogate for the value (§13 #30). Earlier drafts re-pseudonymized fixtures with a separate key; that would break this loop, so it is dropped (§13 #13).
- **The IWS simulator.** In S3 agents build a local simulator that replays recordings by operation and masked request (Annex E §5; re-plan §3.1). It serves contract tests and agent debugging, and answers an unrecorded request with a clear "not recorded" fault, so agents know when a new plan is needed. Tests of IWS's own format validation use synthetic data, not surrogates (§4.2).

### 9.2 Requesting a new live experiment

1. The agent writes a plan under `recording-plans/` (§5.2) in a PR: purpose (the test or question it serves), the calls, and the expected outcome. One plan should answer a whole question, with every variant asked for at once.
2. CI runs `recorder check` and the leak scan.
3. The CTO reviews the plan (a short YAML file) and merges it.
4. The CTO runs it on the trusted machine, batching several plans in one session where possible (§5.1).
5. The CTO commits the masked result in a PR that names the plan, and merges it after CI.
6. Agents continue from the new recording and the simulator.

The CTO's time per loop is about 15–30 minutes (*Inferred*; §11.2). The calendar wait is the CTO's next session, so agents work on the simulator in between. Agents never put a real-looking value in a plan (the leak scan rejects it), never ask for raw output or for DEACTIVE, and never add a non-SITEST endpoint. A plan's text is a request, not an instruction: a plan that asks the CTO for a manual action (a DEACTIVE, a Beta call, a raw reproduction, a run from a branch) is rejected in review, and the CTO's manual calls follow only his own runbook (§5.7, §6.5).

### 9.3 Spike tests in S3

The re-plan runs the S3 spike tests "with agents looping through the masker" (re-plan §4 S3; Annex F §7.2). Under option C the path per test is:

| Test | Path |
|---|---|
| ST-15 | No IWS call; S3 scope, for the production gateway's AWS region |
| ST-01 | Offline, on the WSDL snapshot |
| ST-02 | Offline signature vectors in S2. Positive calls: a recording plan. Negative signatures, clock skew and operation-name case: the harness below |
| ST-03 | Agents, on the masked infoset (masking keeps `xsi:type`, nil versus absent and arrays; §4.1). The ID and PIN round trip is judged on synthetic data, or by the CTO on one raw sample on the trusted machine |
| ST-04 | A write recording plan the CTO runs on test inventory (§5.6); DEACTIVE by the CTO by hand (§5.7) |
| ST-07 | AUTH, FIELD, not found and empty success: recording plans (masked faults keep their shape). "Too many connections!": the harness |
| ST-05 | The harness, in a CTO session: both permits and a third connection; results as counts and fault codes only |
| ST-08 | A metrics-only recorder mode (§13 #8) for both the 10,000-row raw-usage page and the 5,000-row `accountSearch`: row counts, sizes, parse time and field presence, no rows |

**Harness (S3 scope).** A fixed, reviewed program the CTO runs on the trusted machine. It may use both slots and a third connection, sends prebuilt request variants (bad signature, skewed timestamp, wrong-case operation, parallel requests) and returns only fault codes and timings, never a response body. Its review is S3 scope (about 1–2 CTO-hours, *Inferred*).

## 10. Exit criteria and first live steps

### 10.1 Exit criteria

**Reads (opens agent work on recordings):**

1. All tests in §8.2 and §8.5 pass for every read method in the allowlist; `make check` is green (lint, pyright strict, contracts with the §7.3 changes, tests, security with `leak_scan.py`, Terraform, workflows); the `recorder check` CI job runs.
2. Recorded samples: the first recording covers every allowed read method and every service type present in SITEST's data, the runtime detector has zero hits, there are zero unknown elements, the CTO has read the masked output, and it passed the leak scan and gitleaks and is merged.
3. The in-prefix counter (§4.2) reads zero for every type: the reserved prefixes are absent from real data.
4. Beta unreachability: the no-Beta-host test and the transport tests (pinned address, no redirects, certificate name) pass, and the first live step's record of SITEST's and Beta's addresses and certificates is in the runbook (§7.1, §10.2).
5. Recovery: one vault backup has been written to the off-machine target, restored on the trusted machine and opened with the keys from Keeper; the escrow is in place (§6.3).
6. The CTO has reviewed every line of the masker (including the logging filter), the recorder, the gateway signer core, the contract changes and the gate changes.

**Writes (before ST-04):** the hard-block, write-check, idempotency and dry-run tests pass; test inventory is registered; the first write plan is reviewed and merged; one dry run, then one real write on SBD inventory, recorded masked and merged.

These meet the re-plan's S2 exit: leak tests green on recorded samples, and the CTO's line-by-line review.

### 10.2 First live steps (the CTO personally, in order)

The credential arrived on or before 20 Oct 2026 and stays in the CTO's Keeper. No step needs an AWS account, a VM or a hosting provider.

1. **Now, mandatory and first.** From the trusted machine, harvest both SITEST WSDLs, provisioning and reporting (re-plan §10, week 4). No call to Beta. This is a prerequisite for the field map and the allowlist (§4.5, §5.3). Optionally run one `authenticatedPing` on SITEST (WSDL Explorer or SoapUI) to confirm the credential works. One call at a time. Record SITEST's address, port and certificate, and how the Beta name resolves (a lookup only, no connection), for the pinned address and the shared-address check (§7.1).
2. **Trusted machine.** Set it up (§6.5): the recorder user, its exclusion from cloud sync and online backup, the venv from the reviewed commit, the pre-commit hook, the Keeper CLI, `recorder keys init` into Keeper, the backup key, the escrow and the off-machine backup target.
3. **First recording**, once the read code is merged and the shape and red-team tests pass. Agents write `RP-2026-001`; the CTO reviews it. Read allowlist only: system calls on both endpoints, one catalog cascade per service sold, `accountSearch` with `limit` 5 per service type, `getSubscriberAccount` on 2–3 accounts of each type present, `validateDeviceString` on assigned test inventory if any, and `getIwsRequests` over the last hour (which checks the `caller` prefix, §5.8). Dry run first, then the live run.
4. **Classify and repeat.** Read the masked output, the in-prefix counter and the incidents. Agents propose the overrides the samples need (§4.5) in a PR, and the CTO reviews them; the CTO adds the message templates himself (§4.4). Repeat the run until it is clean.
5. **Read exit.** Commit the clean recording by PR and merge it after CI. Run `recorder backup` and the restore test. Agents need no token or environment change to start.
6. **Before ST-04.** Register test inventory (§5.6), review the first write plan, watch its dry run, then run the first write. DEACTIVE stays a manual CTO call, recorded with `recorder note` (§5.7).

## 11. Effort and schedule

### 11.1 CTO-hours for Part 1 (*Inferred*)

Agents write the code, tests, recording plans and the runbook draft. The CTO decides, reviews line by line and runs every live call.

| Work | Low | Expected | High | VM design, expected |
|---|---|---|---|---|
| Design review of this revision and the §13 decisions | 0.5 | 1 | 1.5 | 2.5 |
| Line-by-line review: masking engine (schema validation, tokenization, vault logic, free text and templates, embedded XML, detectors, logging filter), about 1,200–1,800 lines with tests | 3 | 4 | 5.5 | 9 (with the HTTP service, tokens, budgets and admin CLI) |
| Field-map overrides: agents propose a class for every string path with its catalog field name; the CTO reviews | 1 | 1.5 | 2.5 | (inside the 9) |
| Line-by-line review: gateway signer core (signing, envelope, endpoints, transport, guard) and the ST-02 vectors | 1 | 1.5 | 2 | 2 (with the permit ledger, now back in S3) |
| Line-by-line review: recorder (plan loader, allowlist, run refusals, SQLite store, Keeper loading, output, backup), contracts and `CLAUDE.md` changes | 1 | 1.5 | 2 | — |
| Trusted-machine setup: recorder user, sync and backup exclusions, venv, pre-commit hook, Keeper CLI, keys, escrow, backup target | 0.5 | 0.5 | 1 | 1 |
| First live steps: WSDL harvest, first recording, classification rounds, merge (§10.2 steps 1–5) | 1 | 1.5 | 2.5 | 2.5 |
| Signer container, VM provisioning and hardening, backups and alerting | 0 | 0 | 0 | 7 |
| **Reads subtotal** | **8** | **11.5** | **17** | **24** |
| Writes: write-check review, inventory registration, first write plan, dry run and first write | 0.5 | 1 | 1.5 | 6 |
| **S2 total** | **8.5** | **12.5** | **18.5** | **30** |

The expected 12.5 hours sit at the re-plan's S2 budget of 8 / 12 / 15, about 11 hours net of the 1.5 hours of signer-core review moved forward from S3. The high case is above 15 because the field map and the first recordings are the uncertain part: an unknown element or a new template means another round. The lines and CTO-hours of `gateway/signing.py`, `envelope.py` and `transport.py` count toward the K8 budget of the owned SOAP layer (about 2,500 lines or 40 CTO-hours; Annex F §7.3). The CTO-hours log (re-plan §3.5) should record S2 hours separately from S3 for the week-8 calibration. Upkeep after S2 is small: a vault backup after each run, and OS updates the trusted machine gets anyway.

**Split.** Agents: all code, tests, recording plans, override proposals, and the runbook draft. CTO: decisions, reviews, message templates, the secret, the keys, test inventory, every live run, and every DEACTIVE.

### 11.2 Live loops in S3 and S4 without the agent endpoint (*Inferred*)

Without Part 2, every live experiment in S3 and S4 is a recording loop that costs CTO time (§9.2). With Part 2, agents run reads themselves.

| | Part 1 only | With Part 2 activated at week 8 |
|---|---|---|
| One live read experiment | 15–30 min of CTO time (review, run, read, commit) | About 0; agents call the endpoint |
| S3 (about 15–30 experiments) | 4–15 h, about 7 expected | Token minting, a few minutes a day: about 2–3 h |
| S4 (about 10–20 experiments) | 2.5–10 h, about 5 expected | Token minting: about 2 h |
| Fixed cost | 0 | Build 6 / 9.5 / 14 h (§12.5), upkeep about 0.25–0.5 h a week (3–6 h over S3 and S4) |
| **S3 + S4** | **6–25 h, about 12 expected** | **13–25 h, about 18 expected, build included** |

So, honestly: without the agent endpoint, S3 and S4 live loops cost the CTO on the order of **10 more hours** (about 12 expected, range 6–25) of loop work that agents would otherwise do themselves, plus calendar wait, because agents stop at each loop until the CTO's next session. The endpoint does not make that time free: it costs about 9.5 hours to build and about 8–9 hours of token minting and upkeep over S3 and S4. In total CTO-hours the two paths are close (about 12 against 18 expected), so Part 2 pays off in hours only if the loops run well above the counts above (about 50 or more in S3 and S4), and otherwise only if the calendar wait blocks agents for days. That is the test for the week-8 calibration (§12.1). Writes stay CTO-run in both columns. The right-hand column is optimistic: Part 2 serves only the loops after it is built (weeks 9–10 at the earliest), so the S3 loops before then are recording loops in both columns.

### 11.3 Schedule

All dates below are *Inferred*.

- **S2 is on the critical path** (S0 pack status note). Agents start the masking engine on the catalog in weeks 2–3; the field map and allowlist are finalized after the WSDL harvest (§10.2 step 1). The binding constraint is CTO review hours, while S0 still needs 15–20 CTO-hours in weeks 1–3.
- **Read exit:** week 5 (16–22 Nov 2026) expected, at about 11.5 CTO-hours and ~8 h/week of build capacity (re-plan §4.1); week 4 (9–15 Nov 2026) is the best case. The VM design expected week 6. The saving, about 17.5 hours, also leaves room for S1 if TAP files are at risk.
- **Writes:** inside S3's first weeks, before ST-04.
- **S3:** G1 stays expected in month 3 (mid-January 2027). The capacity check for months 1–3 (about 90 h available against about 100 expected for S0–S3; re-plan §4.1) no longer widens by the 16–20 hours the VM design added. The S3 re-baseline must add the recording loops (about 7 h expected, §11.2) and the permit-ledger review moved back (about 0.5 h). So the existing gap of about 10 hours remains and widens by up to about 6.5 hours: S2's 0.5 hour over budget, plus 7.5 hours in S3, minus the 1.5 hours of signer-core review already moved into S2.
- **Week-8 calibration (7–13 Dec 2026):** decides whether Part 2 is activated (§12.1).

No other stage is re-planned here.

## Part 2: the live agent endpoint (later, optional)

## 12. Part 2: live agent endpoint on one VM

### 12.1 When to activate it

Part 2 is decided at the week-8 calibration (7–13 Dec 2026), only if the CTO-run loop has become the bottleneck. Suggested signals (*Inferred*): more than about 4 recording loops a week for two weeks running; agents blocked on recordings for more than about 2 working days at a time; or S3 spike work that needs fast, iterative live debugging (ST-02, ST-03, ST-07). If none holds, S3 and S4 continue with recordings and the simulator.

At activation, before any code: a short design delta to this part, and Legal's review of DigitalOcean's DPA, sub-processors and data location, because a live masker needs the vault on the VM, so real identifiers (encrypted) would then sit at the provider (§13 #26).

### 12.2 Architecture summary

One DigitalOcean droplet runs Docker Compose (decided: DigitalOcean, because Globalsat's Hub already runs on one droplet with Docker Compose; the masker never shares the Hub droplet, a database or a role with anything that holds a production credential):

| Container | Role | Network reach |
|---|---|---|
| `caddy` | TLS on the Globalsat subdomain, certificate from Let's Encrypt, automatic; reverse proxy to the masker | Inbound 443; outbound to the certificate authority |
| `masker` | An HTTP service around the same masking engine: token check, allowlist, unmask, call the signer, mask, detect, record | None off the VM: internal Docker networks only |
| `signer` | The same gateway signer core behind an internal HTTP service, the second implementation of `gateway.sitest_port` (§7.1); the only holder of the SITEST secret; the permit ledger | TCP 8443 to the pinned SITEST address only; reachable only from the masker, with a link token |
| `postgres` | The vault, call log, masked exchanges, permit ledger, flags | None |
| `backup`, `alerter` | Nightly encrypted backup; e-mail alarms | Their own endpoints only |

Agents run in a dedicated cloud environment and send short-lived, CTO-minted tokens (ES256, a fixed `gsm_` prefix that gitleaks and GitHub secret scanning recognize) to the masker host; that environment's network allowlist holds the masker host and not `*.iridium.com`. The request and response shapes, refusal codes and per-session limits of the previous revision (commit `f00407d`, §4 and §10) are the starting point. One IWS test user is shared with the CTO: agent traffic takes at most slot 2 of the user's 2 slots, the CTO's live runs keep slot 1, and agents pause automatically during the CTO's IWS dry runs (S5) and the certification run. The CTO's manual calls (a DEACTIVE) use slot 1 as well, so they never overlap a recording run (§5.7). Agent calls carry the `agent.` caller prefix. Reads first: agent tokens are read-only, and writes stay CTO-run recordings until agent writes are wanted (§12.4).

```text
 Agent session (cloud)                        One DigitalOcean VM
 ┌───────────────────────┐  HTTPS 443  ┌──────────────────────────────────────────────┐
 │ agent code + token    │ ──────────▶ │ cloud firewall + nftables: inbound 443 only  │
 │ allowlist: masker host│             │ caddy (TLS, Let's Encrypt) ──▶ masker         │
 └───────────────────────┘             │   token → policy → unmask → signer → mask     │
                                       │   → detect → record (postgres)               │
 CTO (trusted machine) ── Tailscale ──▶│ SSH on the tailnet only                      │
                                       │ signer: secret, permits, pinned SITEST host ─┼──▶ SITEST :8443 only
                                       └──────────────────────────────────────────────┘
```

### 12.3 Lean security profile

The controls kept when Part 2 is activated:

| Control | What it is |
|---|---|
| Masking, fail-closed, leak tests | The Part 1 engine, field map and detectors unchanged; a runtime block returns `502 MASKING_BLOCKED`, disables the method and raises an alarm; the shape and red-team tests extend to the HTTP service |
| Reads first | Agent tokens carry read scopes only (`read:catalog`, `read:inventory` by default); row caps, rate limits and daily budgets of distinct records as in the previous revision |
| DEACTIVE, CLOSED and Beta blocks | The hard blocks in the masker and again in the signer's guard; pinned SITEST host and address, no Beta endpoint in code, no working DNS resolver in the containers (an unroutable upstream that nftables drops) |
| The secret only in the signer container, encrypted at rest | A sops file encrypted with age, decrypted at start into the signer's tmpfs only; the masker container never holds it |
| Token authentication | ES256 with a pinned key id; `jku`, `x5u` and `jwk` ignored; a lifetime cap per scope in code (read tokens 4 h); `jti` revocation and a global "not before" time; bare 401 before any parsing; the signing key is a software key in Keeper, used only on the trusted machine |
| Outbound firewall to SITEST only | Provider cloud firewall and an nftables table of its own: the only IWS destination is the pinned SITEST address on 8443, from the signer's subnet only; the masker and Postgres sit on internal networks with no route off the VM; Caddy, backup and alerter reach 443 only (not limited by name until the egress proxy, §12.4 #5); every other container connection is dropped |
| SSH only over Tailscale | `sshd` listens on the tailnet interface only, and no 22 rule exists in the cloud firewall; passphrase-protected ed25519 keys from Keeper, publickey only, no root, no passwords; the tailnet ACL admits only the CTO's trusted machine (decided, replacing the per-session firewall rule) |
| Automatic TLS | Caddy with Let's Encrypt through the TLS-ALPN challenge on 443, admin API off; the CTO adds the subdomain's record in Globalsat's DNS, which the CTO controls |
| Encrypted backups | Nightly `pg_dump`, streamed through age to a key held in Keeper, to object storage in another region; 30 days; one restore tested at activation |
| E-mail alarms | An alerter sends enumerated codes and bucketed counts, never values, by e-mail to a CTO-only mailbox no agent connector can read: runtime block, DEACTIVE attempt, `AUTH` fault, "Too many connections!", signer start, backup failure, certificate expiry, disk; a free dead-man's-switch heartbeat e-mails the CTO if the VM goes silent |
| Provider account | Only the CTO in the DigitalOcean team, with TOTP 2FA on the CTO's phone; the provider API token in Keeper |
| Containers and updates | Non-root UIDs, read-only root file systems, `no-new-privileges`, capabilities dropped, no Docker socket; images built from a reviewed commit and pinned; unattended security updates with automatic reboots |
| Kill switch | Remove the 443 rule; power off in the provider console; pause flag; revoke tokens; stop the signer |

### 12.4 Deferred controls

The VM design of the previous revision had more. Each item below is deferred to S2b (agent writes) or to production, with what Part 2 does until then:

1. **Two-machine signing of plans and inventory, with the signer's own write guard** (S2b, when agents are to write). Until then agents only read; writes stay CTO-run recordings (§5.6).
2. **Object-locked backups** (versioning plus object lock, or another provider's bucket that can lock). Until then a compromised VM could delete its backups; the vault backup on the trusted machine remains.
3. **A separate key container** (`keyholder`) for `K_mask` and the vault key. Until then they sit in the masker process.
4. **Hand-pasted unlock keys** (the age identity only in Keeper, pasted after each reboot). Until then a root-only key file on the VM, so the VM reboots unattended.
5. **The host egress proxy with a domain allowlist.** Until then host and Caddy egress on 443 is not limited by name; the signer and masker limits above still hold.
6. **gVisor** (or `userns-remap`) for the masker and Caddy. Until then Docker's default seccomp and AppArmor profiles.
7. **The SSH-login watcher and security-log shipping** (a `pam_exec` alarm, `sudo` and firewall-drop alarms, logs to an append-only bucket). Until then Tailscale's own login records and the provider's audit log.
8. **The fresh-login Keeper and scoped-token habits** (a fresh Keeper login for each minting session; per-test `read:sp` tokens; the mint log matched to the first use of each `jti` in a daily digest). Until then default read tokens, minted as needed.
9. **Smaller items:** NTS-authenticated time, removal of the provider's guest agents, the Caddy rate-limit module (until then per-source limits in nftables), and a Network-secret injection of the token (until then the environment variable `MASKER_TOKEN`).

### 12.5 Cost if activated

| Item | Estimate (*Inferred*) |
|---|---|
| Build: masker HTTP service, token minting and the code side of auth, the signer container and link, the permit ledger, the Postgres vault and import from the trusted machine, lean provisioning (Compose, nftables, Caddy, Tailscale, sops), backups and the e-mail alerter, first deploy, kill-switch test | 6 / 9.5 / 14 CTO-hours |
| Upkeep: alarms, monthly image rebuilds, token minting | About 0.25–0.5 h a week, plus a few minutes a day for tokens |
| Later, if agents are to write (S2b): write guard, two-machine signing | About 4–6 CTO-hours more |
| VM (2 vCPU / 2–4 GB) | ≈ US$18–24 a month |
| Block-storage volume for Postgres | ≈ US$1–2 a month |
| Object storage for backups (DigitalOcean Spaces, smallest plan) | ≈ US$5 a month |
| Tailscale, e-mail and heartbeat services | ≈ US$0 on free plans; ≈ US$6 a month if Tailscale's terms need a paid plan for business use (to verify) |
| **Total run cost** | **≈ US$24–31 a month, up to ≈ 37** |

Nothing in AWS is created for Part 2. The production gateway (S4) stays in AWS and is decided then.

## 13. Decisions and open items

The list is numbered afresh in this revision. Items marked **Open** still need the CTO (and, where named, Legal or Iridium).

1. **Shape of S2. Decided (CTO, 20 Oct 2026, option C):** the masking engine plus a CTO-run recorder on the trusted machine. No VM, no internet-facing endpoint, no agent tokens and no run cost in S2 (§1).
2. **Masking scheme. Decided:** keyed tokenization with a vault and reserved-prefix surrogates (§4.6). Not FF1.
3. **How SITEST is called. Decided:** S2 builds the gateway's SITEST signer core under `gateway/`, called in process through `gateway.sitest_port`, with the contract and `CLAUDE.md` changes of §7.3. Part 2 adds a signer container behind the same port.
4. **IWS users. Decided (CTO, 20 Oct 2026):** one SITEST IWS user, shared with the CTO; no second user is requested. Follow-ups in `Globalsat-Group/IWS`: a note on Annex D §2.4 and §2.9, whose separate SITEST users (`gs-cert`, `gs-ci`) no longer exist, and the Annex B question in #24.
5. **Beta and production unreachable. Decided:** pinned SITEST host and address, no Beta endpoint anywhere in code, a test that keeps every other Iridium host out of `src/` (§7.1).
6. **DEACTIVE and `CLOSED`. Decided:** both hard-blocked in the recorder and again in the signer core, with no flag that lifts the block. The CTO's own DEACTIVE is a manual call from the trusted machine, recorded with `recorder note` (§5.7).
7. **Writes. Decided:** only on assigned test inventory, only in a reviewed plan the CTO runs with `--writes`, after a dry run, confirmed per write (§5.6). Device swaps stay out; if a later test needs them, add a CTO-confirmed class with each {from, to} pair listed in the plan.
8. **Raw usage and inline reports. Decided:** refused in S2. For ST-08 in S3, a metrics-only recorder mode (row counts, sizes, parse time, field presence, no rows) (§9.3). Masked rows, with coordinates generalized, are considered only after the read exit has run clean.
9. **WSDL snapshot and field-map location. Decided:** the snapshot comes forward from S3 to S2 under `gateway/wsdl/`, with the generated field map under `gateway/wsdl/fieldmap/`, subject to the interim confidentiality rule (re-plan §8.6).
10. **Vault. Decided (CTO, 20 Oct 2026):** a SQLite file on the trusted machine with values encrypted under a vault key held in Keeper, and an encrypted off-machine backup. Real identifiers never reach agents, git or any cloud service (§6).
11. **SITEST secret. Decided (CTO, 20 Oct 2026):** stays in Keeper and is loaded only for a live run, into the recorder's memory (§6.2).
12. **Recording plans. Decided:** YAML under `recording-plans/`, checked in CI, reviewed by the CTO in a PR, run only from a clean checkout of a commit on `main` (§5.1, §5.2). Add the path to CODEOWNERS.
13. **Recordings carry vault surrogates. Decided:** committed recordings are not re-pseudonymized, so agents can name records in later plans (§9.1). They are pseudonymized personal data while the vault holds their values (#21).
14. **Trusted machine and software keys. Decided (CTO, 20 Oct 2026, risk accepted):** one named device, no AI agent under the OS user that holds Keeper or as an administrator, only reviewed code from `main`, no hardware keys; keys and the secret loaded from Keeper only for a run (§6.5). A compromised machine or Keeper session exposes the secret and every key; that exposure predates option C.
15. **Retention. Decided as working periods:** vault values deleted 90 days after last use, slots kept forever as tombstones; run log 18 months; vault backups 30 days (§6.4). Final periods are #21.
16. **Part 2. Decided as an optional add-on (CTO, 20 Oct 2026):** decided at the week-8 calibration (7–13 Dec 2026), with its decisions already taken: DigitalOcean; the one IWS test user shared with the CTO; SSH only over Tailscale, no public SSH; automatic TLS via Caddy and Let's Encrypt; software keys in Keeper; alarms by e-mail to the CTO; the CTO adds the subdomain record in Globalsat's DNS; the lean security profile with the deferred controls of §12.4.
17. **Data protection at the hosting provider. Decided:** not needed for S2, because Part 1 places no unmasked SITEST data at a hosting provider (masked recordings at GitHub and in agent transcripts are #21). Required before Part 2 is activated (#26).
18. **S2 budget. Decided (CTO, 20 Oct 2026):** 8.5 / 12.5 / 18.5 CTO-hours (*Inferred*, §11.1), replacing the 19 / 30 / 42 of the VM design. S3 is re-baselined with the recording loops (about 7 h expected, §11.2) before its work starts; re-plan 1.4 carries the figures.
19. **The trusted machine. Decided (CTO, 20 Oct 2026); risks accepted:** the CTO's laptop, under the CTO's normal OS user, with the CTO's normal Keeper (§6.5). Agent sessions keep reaching GitHub through the CTO's account (re-plan §3.3, accepted risk). Stated plainly: a live run trusts whatever is on `main`, and an agent with that access could merge a change that the CTO then runs with Keeper unlocked, exposing the keys, the vault and the SITEST secret (and so Beta). The controls are the CTO's review of every merge before a recording session and the run-time rules of §6.5. Device name [FILL]. Revisit when the bot identity exists, and before Part 2.
20. **Off-machine vault backup. Decided (CTO, 20 Oct 2026): a Keeper file attachment**, age-encrypted, ciphertext only. Keeper also holds the vault key, so Keeper alone can decrypt the backup; accepted. Recommended cheap hardening: encrypt the backup to an age passphrase the CTO keeps outside Keeper (§6.3).
21. **Final retention and the basis for pseudonymized data. Open, for Legal:** the final periods per country; the basis for masked recordings kept in git history and for masked data in agent transcripts held by the agent provider (§6.4).
22. **Certification-month evidence. Open:** agents no longer call IWS in S2, but recording calls share the one IWS user, so the User Activity Report for the month counts them. Recommend that the evidence index states this and separates the traffic by the `caller` prefix (`rec.`, later `agent.`, against `gs.`), and that no recording runs in a certification month unless needed; ask Iridium whether that satisfies its certification team (Annex B).
23. **Iridium's confidentiality question. Open:** whether masked recordings (IWS response shapes) and the WSDL snapshot may sit in this private repository under the interim rule (re-plan §8.6). Until it is answered, the snapshot stays under `gateway/` only and recordings carry no catalog descriptions.
24. **Questions for Iridium. Open:** whether the 2-request limit counts per user across SITEST and Beta (Annex B); the secret rotation procedure and lead time (re-plan §11.1 Q4); port 8443 or 8843 (Annex D §1). Checked in the first recording instead: whether `getIwsRequests` shows `caller` as sent (§5.8). Until Iridium answers the first, the CTO makes Beta calls one at a time and never during a recording run.
25. **Week-8 calibration. Open:** activate Part 2 or not, against the signals of §12.1.
26. **At Part 2 activation. Open:** the subdomain name [FILL]; the e-mail sending service and the heartbeat service; whether Tailscale's free plan fits business use; moving the vault to the VM and Legal's review of DigitalOcean's DPA, sub-processors, data location and cross-border transfer before any SITEST data reaches it; and which deferred controls (§12.4) to pull forward.
27. **`xml:lang`. Decided (CTO, 21 Oct 2026):** allowed as a plain attribute, because SOAP 1.2 faults carry it. Only a plain language tag is accepted (§4.5).
28. **Large responses. Decided (CTO, 21 Oct 2026):** responses above about 2,000 rows hit `MASKING_TIMEOUT` and are blocked, so they fail closed (§8.4). Accepted for S2. Revisited if a plan needs large reports.
29. **The recorder's own `caller`. Decided (CTO, 21 Oct 2026):** the recorder's `caller` value is kept unmasked (built in S2 PR D2). Only values matching `rec.RP-YYYY-NNN` are kept, and only in caller fields (§3.1, §5.8).
30. **Tombstones. Decided (CTO, 21 Oct 2026):** a tombstone no longer records which value it held. So a value that returns after its vault row was deleted gets a new surrogate, at the next free counter. The old surrogate stays reserved forever, so it never comes to mean another value. Deleting vault rows still does not anonymize old recordings (§4.3, §6.4).
31. **`getQueueEntries` bounds. Open, for the CTO at PR W:** the catalog gives `getQueueEntries` only `Endpoint`, `status` and `createdBy`, so the window and `Limit` of §5.3 cannot be enforced on it. Until W confirms its inputs against the WSDL, it is bounded only by the recorder-set `createdBy` (§5.5 step 8; it may be the IWS username the CTO shares, #4), the fail-closed `MASKING_TIMEOUT` at about 2,000 rows (#28) and the CTO's plan review. Its list output carries no subscriber identifier. The CTO accepts that or refuses the method.
