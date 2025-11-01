;; AccessContract.clar

(define-constant ERR-NOT-REGISTERED (err u300))
(define-constant ERR-NOT-OWNER (err u301))
(define-constant ERR-NOT-GRANTEE (err u302))
(define-constant ERR-INVALID-GRANT-TYPE (err u303))
(define-constant ERR-INVALID-EXPIRY (err u304))
(define-constant ERR-GRANT-ALREADY-EXISTS (err u305))
(define-constant ERR-GRANT-NOT-FOUND (err u306))
(define-constant ERR-INVALID-REASON-LENGTH (err u307))
(define-constant ERR-MAX-GRANTS-EXCEEDED (err u308))
(define-constant ERR-AUDIT-LOG-FAILED (err u309))
(define-constant ERR-INVALID-AUDIT-TYPE (err u310))
(define-constant ERR-NOT-AUTHORIZED (err u311))
(define-constant ERR-INVALID-ACCESS-LEVEL (err u312))
(define-constant ERR-GROUP-NOT-FOUND (err u313))
(define-constant ERR-INVALID-GROUP-MEMBERSHIP (err u314))

(define-data-var next-grant-id uint u0)
(define-data-var max-grants-per-record uint u50)
(define-data-var audit-enabled bool true)

(define-map access-grants
  { record-id: uint, grantee: principal }
  {
    grant-type: (string-ascii 20),
    expiry: (optional uint),
    reason: (string-ascii 200),
    level: uint,
    granted-at: uint,
    granter: principal,
    revoked: bool
  }
)

(define-map record-owners uint principal)
(define-map record-grant-counts uint uint)
(define-map group-members { group-id: uint, member: principal } bool)
(define-map groups uint { name: (string-ascii 50), creator: principal, active: bool })

(define-map audit-logs
  uint
  {
    action: (string-ascii 50),
    actor: principal,
    record-id: uint,
    timestamp: uint,
    details: (string-ascii 200)
  }
)

(define-data-var next-audit-id uint u0)

(define-read-only (get-grant (record-id uint) (grantee principal))
  (map-get? access-grants { record-id: record-id, grantee: grantee })
)

(define-read-only (get-record-owner (record-id uint))
  (map-get? record-owners record-id)
)

(define-read-only (get-grant-count (record-id uint))
  (map-get? record-grant-counts record-id)
)

(define-read-only (is-group-member (group-id uint) (member principal))
  (default-to false (map-get? group-members { group-id: group-id, member: member }))
)

(define-read-only (get-group (group-id uint))
  (map-get? groups group-id)
)

(define-read-only (get-audit-log (log-id uint))
  (map-get? audit-logs log-id)
)

(define-read-only (has-access (record-id uint) (user principal))
  (let (
        (grant (unwrap! (get-grant record-id user) false))
        (expired (match (get expiry grant) exp (>= block-height exp) false))
      )
    (and (not (get revoked grant)) (not expired))
  )
)

(define-private (validate-grant-type (gt (string-ascii 20)))
  (if (or (is-eq gt "individual") (is-eq gt "group") (is-eq gt "temporary"))
      (ok true)
      (err ERR-INVALID-GRANT-TYPE))
)

(define-private (validate-expiry (exp (optional uint)))
  (match exp
    e (if (>= e block-height)
          (ok true)
          (err ERR-INVALID-EXPIRY))
    (ok true))
)

(define-private (validate-reason (reason (string-ascii 200)))
  (if (and (> (len reason) u0) (<= (len reason) u200))
      (ok true)
      (err ERR-INVALID-REASON-LENGTH))
)

(define-private (validate-access-level (level uint))
  (if (<= level u3)
      (ok true)
      (err ERR-INVALID-ACCESS-LEVEL))
)

(define-private (log-audit (action (string-ascii 50)) (record-id uint) (details (string-ascii 200)))
  (if (var-get audit-enabled)
      (let (
            (log-id (var-get next-audit-id))
          )
        (map-set audit-logs log-id
          {
            action: action,
            actor: tx-sender,
            record-id: record-id,
            timestamp: block-height,
            details: details
          }
        )
        (var-set next-audit-id (+ log-id u1))
        (ok true))
      (ok true))
)

(define-public (set-record-owner (record-id uint))
  (let ((caller tx-sender))
    (asserts! (is-none (get-record-owner record-id)) (err ERR-NOT-OWNER))
    (map-set record-owners record-id caller)
    (try! (log-audit "owner-set" record-id "Owner set"))
    (ok true))
)

(define-public (grant-access (record-id uint) (grantee principal) (grant-type (string-ascii 20)) (expiry (optional uint)) (reason (string-ascii 200)) (level uint))
  (let (
        (caller tx-sender)
        (owner (unwrap! (get-record-owner record-id) ERR-NOT-OWNER))
        (count (default-to u0 (get-grant-count record-id)))
        (key { record-id: record-id, grantee: grantee })
      )
    (asserts! (is-eq caller owner) (err ERR-NOT-OWNER))
    (try! (validate-grant-type grant-type))
    (try! (validate-expiry expiry))
    (try! (validate-reason reason))
    (try! (validate-access-level level))
    (asserts! (< count (var-get max-grants-per-record)) (err ERR-MAX-GRANTS-EXCEEDED))
    (asserts! (is-none (map-get? access-grants key)) (err ERR-GRANT-ALREADY-EXISTS))
    (map-set access-grants key
      {
        grant-type: grant-type,
        expiry: expiry,
        reason: reason,
        level: level,
        granted-at: block-height,
        granter: caller,
        revoked: false
      }
    )
    (map-set record-grant-counts record-id (+ count u1))
    (try! (log-audit "access-granted" record-id "Access granted"))
    (ok true))
)

(define-public (revoke-access (record-id uint) (grantee principal))
  (let (
        (caller tx-sender)
        (owner (unwrap! (get-record-owner record-id) ERR-NOT-OWNER))
        (grant (unwrap! (map-get? access-grants { record-id: record-id, grantee: grantee }) ERR-GRANT-NOT-FOUND))
      )
    (asserts! (is-eq caller owner) (err ERR-NOT-OWNER))
    (asserts! (not (get revoked grant)) (err ERR-GRANT-NOT-FOUND))
    (map-set access-grants { record-id: record-id, grantee: grantee }
      (merge grant { revoked: true }))
    (try! (log-audit "access-revoked" record-id "Access revoked"))
    (ok true))
)

(define-public (grant-group-access (record-id uint) (group-id uint) (expiry (optional uint)) (reason (string-ascii 200)) (level uint))
  (let (
        (caller tx-sender)
        (owner (unwrap! (get-record-owner record-id) ERR-NOT-OWNER))
        (group (unwrap! (get-group group-id) ERR-GROUP-NOT-FOUND))
      )
    (asserts! (is-eq caller owner) (err ERR-NOT-OWNER))
    (try! (validate-expiry expiry))
    (try! (validate-reason reason))
    (try! (validate-access-level level))
    (let ((proxy-key { record-id: record-id, grantee: (get creator group) }))
      (asserts! (is-none (map-get? access-grants proxy-key)) (err ERR-GRANT-ALREADY-EXISTS))
      (map-set access-grants proxy-key
        {
          grant-type: "group",
          expiry: expiry,
          reason: reason,
          level: level,
          granted-at: block-height,
          granter: caller,
          revoked: false
        }
      )
    )
    (try! (log-audit "group-access-granted" record-id "Group access granted"))
    (ok true))
)

(define-public (create-group (group-name (string-ascii 50)))
  (let ((caller tx-sender)
        (group-id (var-get next-grant-id)))
    (asserts! (and (> (len group-name) u0) (<= (len group-name) u50)) (err ERR-INVALID-REASON-LENGTH))
    (asserts! (is-none (get-group group-id)) (err ERR-GROUP-ALREADY-EXISTS))
    (map-set groups group-id
      {
        name: group-name,
        creator: caller,
        active: true
      }
    )
    (var-set next-grant-id (+ group-id u1))
    (try! (log-audit "group-created" u0 "Group created"))
    (ok group-id))
)

(define-public (add-group-member (group-id uint) (member principal))
  (let (
        (group (unwrap! (get-group group-id) ERR-GROUP-NOT-FOUND))
        (caller tx-sender)
      )
    (asserts! (is-eq caller (get creator group)) (err ERR-NOT-OWNER))
    (asserts! (get active group) (err ERR-INVALID-GROUP-MEMBERSHIP))
    (map-set group-members { group-id: group-id, member: member } true)
    (try! (log-audit "member-added" u0 "Member added"))
    (ok true))
)

(define-public (remove-group-member (group-id uint) (member principal))
  (let (
        (group (unwrap! (get-group group-id) ERR-GROUP-NOT-FOUND))
        (caller tx-sender)
      )
    (asserts! (is-eq caller (get creator group)) (err ERR-NOT-OWNER))
    (map-delete group-members { group-id: group-id, member: member })
    (try! (log-audit "member-removed" u0 "Member removed"))
    (ok true))
)

(define-public (set-max-grants (new-max uint))
  (asserts! (is-eq tx-sender (get-record-owner u0)) (err ERR-NOT-AUTHORIZED))
  (asserts! (> new-max u0) (err ERR-INVALID-MAX-GRANTS-EXCEEDED))
  (var-set max-grants-per-record new-max)
  (try! (log-audit "config-updated" u0 "Max grants updated"))
  (ok true))
  

(define-public (toggle-audit (enabled bool))
  (asserts! (is-eq tx-sender (get-record-owner u0)) (err ERR-NOT-AUTHORIZED))
  (var-set audit-enabled enabled)
  (try! (log-audit "audit-toggled" u0 (if enabled "enabled" "disabled")))
  (ok true))