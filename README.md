# ChainCare: Decentralized Telemedicine Platform

## Overview

ChainCare is a Web3-based telemedicine application built on the Stacks blockchain using Clarity smart contracts. It enables secure, patient-controlled storage of consultation records on the blockchain, ensuring immutability, privacy, and transparency. Users access the platform through a standard video call interface (e.g., integrated with WebRTC for real-time consultations), while all critical data—such as consultation summaries, prescriptions, and access logs—is hashed and stored on-chain.

The frontend can be built with React or similar, integrating with the Stacks wallet (e.g., Hiro Wallet) for authentication and transactions. Video calls are handled off-chain for performance, but metadata (e.g., call timestamps, participant IDs, and record hashes) is committed to the blockchain post-consultation.

This project solves real-world problems in healthcare:
- **Data Privacy and Security**: Traditional telemedicine platforms are vulnerable to data breaches. ChainCare uses blockchain for tamper-proof records, with hashes ensuring sensitive data (e.g., full medical notes) remains off-chain while proofs are on-chain.
- **Patient Empowerment**: Patients own and control access to their records, reducing reliance on centralized providers and enabling seamless sharing with doctors worldwide.
- **Interoperability and Accessibility**: Records are globally accessible without intermediaries, aiding cross-border telemedicine and reducing administrative overhead.
- **Fraud Prevention**: Immutable logs prevent alteration of consultation histories, aiding insurance claims and regulatory compliance (e.g., HIPAA-inspired privacy via encryption and access controls).
- **Cost Efficiency**: Decentralized payments eliminate middlemen fees, and on-chain scheduling reduces no-shows through automated reminders and stakes.
- **Auditability**: Transparent logging helps in disputes, audits, or legal cases, addressing issues like medical malpractice claims.

The project involves 7 solid smart contracts written in Clarity, focusing on modularity, security (e.g., role-based access, non-reentrancy), and efficiency. Contracts are designed to minimize gas costs by storing only hashes and essential metadata on-chain.

## Architecture

- **Frontend**: Web app with video call interface (WebRTC via libraries like Twilio or PeerJS). Users connect their Stacks wallet to interact with contracts.
- **Backend**: Node.js or similar for off-chain logic (e.g., encrypting records, generating video call links). IPFS or similar for storing full encrypted records, with hashes on-chain.
- **Blockchain**: Stacks (Bitcoin-secured via PoX). Contracts handle registration, records, access, appointments, prescriptions, payments, and audits.
- **Workflow**:
  1. Users register as patient or doctor.
  2. Schedule appointment (on-chain for immutability).
  3. Conduct video call off-chain.
  4. Post-call, store record hash on-chain.
  5. Grant/revoke access permissions.
  6. Issue prescriptions and handle payments.
  7. Audit actions as needed.

## Smart Contracts

All contracts are written in Clarity. They are designed to be composable, with clear error handling and public/read-only functions. Deploy them on Stacks using the Clarinet tool or Hiro's developer console.

### 1. RegistryContract.clar
Handles user registration with roles (patient, doctor). Doctors must provide verifiable credentials (hashed for privacy).

```clarity
;; RegistryContract.clar

(define-constant ERR-ALREADY-REGISTERED (err u100))
(define-constant ERR-NOT-AUTHORIZED (err u101))
(define-constant ROLE-PATIENT u1)
(define-constant ROLE-DOCTOR u2)

(define-map Users principal { role: uint, credentials-hash: (optional (buff 32)) })

(define-public (register-patient)
  (let ((caller tx-sender))
    (if (is-some (map-get? Users caller))
      ERR-ALREADY-REGISTERED
      (begin
        (map-set Users caller { role: ROLE-PATIENT, credentials-hash: none })
        (ok true)))))

(define-public (register-doctor (credentials-hash (buff 32)))
  (let ((caller tx-sender))
    (if (is-some (map-get? Users caller))
      ERR-ALREADY-REGISTERED
      (begin
        (map-set Users caller { role: ROLE-DOCTOR, credentials-hash: (some credentials-hash) })
        (ok true)))))

(define-read-only (get-user-role (user principal))
  (match (map-get? Users user)
    info (get role info)
    none))

(define-read-only (is-doctor (user principal))
  (is-eq (default-to u0 (get-user-role user)) ROLE-DOCTOR))
```

### 2. RecordContract.clar
Stores consultation record hashes. Only registered users can add records; hashes ensure privacy.

```clarity
;; RecordContract.clar

(use-trait registry .RegistryContract.Users)

(define-constant ERR-NOT-REGISTERED (err u200))
(define-constant ERR-INVALID-HASH (err u201))

(define-map Records uint { patient: principal, doctor: principal, timestamp: uint, record-hash: (buff 32) })
(define-data-var next-record-id uint u1)

(define-public (store-record (patient principal) (record-hash (buff 32)))
  (let ((caller tx-sender)
        (record-id (var-get next-record-id)))
    (if (not (is-doctor caller))
      ERR-NOT-REGISTERED
      (if (> (len record-hash) u0)
        (begin
          (map-set Records record-id { patient: patient, doctor: caller, timestamp: block-height, record-hash: record-hash })
          (var-set next-record-id (+ record-id u1))
          (ok record-id))
        ERR-INVALID-HASH))))

(define-read-only (get-record (record-id uint))
  (map-get? Records record-id))
```

### 3. AccessContract.clar
Manages permissions for record access. Patients grant/revoke access to doctors or third parties.

```clarity
;; AccessContract.clar

(use-trait records .RecordContract.Records)

(define-constant ERR-NO-PERMISSION (err u300))
(define-constant ERR-NOT-OWNER (err u301))

(define-map AccessGrants { record-id: uint, grantee: principal } bool)

(define-public (grant-access (record-id uint) (grantee principal))
  (let ((caller tx-sender)
        (record (unwrap! (get-record record-id) ERR-NO-PERMISSION)))
    (if (is-eq (get patient record) caller)
      (begin
        (map-set AccessGrants { record-id: record-id, grantee: grantee } true)
        (ok true))
      ERR-NOT-OWNER)))

(define-public (revoke-access (record-id uint) (grantee principal))
  (let ((caller tx-sender)
        (record (unwrap! (get-record record-id) ERR-NO-PERMISSION)))
    (if (is-eq (get patient record) caller)
      (begin
        (map-delete AccessGrants { record-id: record-id, grantee: grantee })
        (ok true))
      ERR-NOT-OWNER)))

(define-read-only (has-access (record-id uint) (user principal))
  (default-to false (map-get? AccessGrants { record-id: record-id, grantee: user })))
```

### 4. AppointmentContract.clar
Schedules appointments on-chain, including video call metadata hashes.

```clarity
;; AppointmentContract.clar

(use-trait registry .RegistryContract.Users)

(define-constant ERR-INVALID-APPOINTMENT (err u400))

(define-map Appointments uint { patient: principal, doctor: principal, time: uint, call-hash: (optional (buff 32)) })
(define-data-var next-appointment-id uint u1)

(define-public (schedule-appointment (doctor principal) (time uint))
  (let ((caller tx-sender)
        (appt-id (var-get next-appointment-id)))
    (if (and (is-doctor doctor) (not (is-eq caller doctor)))
      (begin
        (map-set Appointments appt-id { patient: caller, doctor: doctor, time: time, call-hash: none })
        (var-set next-appointment-id (+ appt-id u1))
        (ok appt-id))
      ERR-INVALID-APPOINTMENT)))

(define-public (add-call-hash (appt-id uint) (call-hash (buff 32)))
  (let ((caller tx-sender)
        (appt (unwrap! (map-get? Appointments appt-id) ERR-INVALID-APPOINTMENT)))
    (if (or (is-eq (get patient appt) caller) (is-eq (get doctor appt) caller))
      (begin
        (map-set Appointments appt-id (merge appt { call-hash: (some call-hash) }))
        (ok true))
      ERR-INVALID-APPOINTMENT)))

(define-read-only (get-appointment (appt-id uint))
  (map-get? Appointments appt-id))
```

### 5. PrescriptionContract.clar
Issues and verifies prescriptions linked to consultations.

```clarity
;; PrescriptionContract.clar

(use-trait records .RecordContract.Records)

(define-constant ERR-NOT-DOCTOR (err u500))

(define-map Prescriptions uint { record-id: uint, pres-hash: (buff 32), issued-at: uint })
(define-data-var next-pres-id uint u1)

(define-public (issue-prescription (record-id uint) (pres-hash (buff 32)))
  (let ((caller tx-sender)
        (pres-id (var-get next-pres-id))
        (record (unwrap! (get-record record-id) ERR-NOT-DOCTOR)))
    (if (is-eq (get doctor record) caller)
      (begin
        (map-set Prescriptions pres-id { record-id: record-id, pres-hash: pres-hash, issued-at: block-height })
        (var-set next-pres-id (+ pres-id u1))
        (ok pres-id))
      ERR-NOT-DOCTOR)))

(define-read-only (get-prescription (pres-id uint))
  (map-get? Prescriptions pres-id))
```

### 6. PaymentContract.clar
Handles STX payments for consultations, with escrow for disputes.

```clarity
;; PaymentContract.clar

(use-trait appointments .AppointmentContract.Appointments)

(define-constant ERR-INSUFFICIENT-FUNDS (err u600))
(define-constant FEE-PERCENT u5) ;; 5% platform fee

(define-map Escrows uint { amount: uint, payer: principal, payee: principal, released: bool })

(define-public (pay-for-appointment (appt-id uint) (amount uint))
  (let ((caller tx-sender)
        (appt (unwrap! (get-appointment appt-id) ERR-INSUFFICIENT-FUNDS)))
    (if (is-eq (get patient appt) caller)
      (try! (stx-transfer? amount caller (as-contract tx-sender)))
      ERR-INSUFFICIENT-FUNDS)
    (map-set Escrows appt-id { amount: amount, payer: caller, payee: (get doctor appt), released: false })
    (ok true)))

(define-public (release-payment (appt-id uint))
  (let ((caller tx-sender)
        (escrow (unwrap! (map-get? Escrows appt-id) ERR-INSUFFICIENT-FUNDS)))
    (if (is-eq (get payer escrow) caller)
      (let ((fee (/ (* (get amount escrow) FEE-PERCENT) u100))
            (net-amount (- (get amount escrow) fee)))
        (try! (as-contract (stx-transfer? net-amount tx-sender (get payee escrow))))
        (try! (as-contract (stx-transfer? fee tx-sender (as-contract tx-sender)))) ;; Platform fee to contract
        (map-set Escrows appt-id (merge escrow { released: true }))
        (ok true))
      ERR-INSUFFICIENT-FUNDS)))
```

### 7. AuditContract.clar
Logs all actions for transparency and auditing.

```clarity
;; AuditContract.clar

(define-map AuditLogs uint { action: (string-ascii 64), actor: principal, timestamp: uint, details: (optional (buff 128)) })
(define-data-var next-log-id uint u1)

(define-public (log-action (action (string-ascii 64)) (details (optional (buff 128))))
  (let ((log-id (var-get next-log-id)))
    (map-set AuditLogs log-id { action: action, actor: tx-sender, timestamp: block-height, details: details })
    (var-set next-log-id (+ log-id u1))
    (ok log-id)))

(define-read-only (get-log (log-id uint))
  (map-get? AuditLogs log-id))
```

## Deployment

1. Install Clarinet: `cargo install clarinet`.
2. Create a new project: `clarinet new chaincare`.
3. Add the above contracts to `contracts/` directory.
4. Configure `Clarinet.toml` with dependencies if needed.
5. Test locally: `clarinet test`.
6. Deploy to Stacks testnet/mainnet via Clarinet or Hiro console.
7. Integrate with frontend using `@stacks/connect` for wallet interactions.

## Usage

- **Register**: Call `register-patient` or `register-doctor`.
- **Schedule**: Use `schedule-appointment`.
- **Consult**: Off-chain video call, then `store-record` and `add-call-hash`.
- **Access**: `grant-access` for sharing.
- **Prescribe**: `issue-prescription`.
- **Pay**: `pay-for-appointment` and `release-payment`.
- **Audit**: Query `get-log` for history.

## Security Considerations

- Use hashes for sensitive data to comply with privacy laws.
- Role checks prevent unauthorized actions.
- No reentrancy risks due to Clarity's design.
- Audit contracts before mainnet deployment.

## Future Enhancements

- Integrate NFTs for patient health passports.
- Add DAO governance for platform fees.
- Support for multi-chain (e.g., Bitcoin L2).