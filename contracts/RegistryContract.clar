;; RegistryContract.clar

(define-constant ERR-ALREADY-REGISTERED u100)
(define-constant ERR-NOT-AUTHORIZED u101)
(define-constant ERR-INVALID-CREDENTIALS-HASH u102)
(define-constant ERR-INVALID-SPECIALTY u103)
(define-constant ERR-INVALID-LOCATION u104)
(define-constant ERR-INVALID-VERIFICATION-CODE u105)
(define-constant ERR-DOCTOR-NOT-VERIFIED u106)
(define-constant ERR-INVALID-UPDATE-PARAM u107)
(define-constant ERR-MAX-USERS-EXCEEDED u108)
(define-constant ERR-AUTHORITY-NOT-SET u109)
(define-constant ERR-INVALID-ROLE u110)
(define-constant ERR-VERIFICATION-EXPIRED u111)
(define-constant ERR-INVALID-TIMESTAMP u112)

(define-constant ROLE-PATIENT u1)
(define-constant ROLE-DOCTOR u2)
(define-constant ROLE-ADMIN u3)

(define-data-var next-user-id uint u0)
(define-data-var max-users uint u5000)
(define-data-var registration-fee uint u500)
(define-data-var authority-contract (optional principal) none)
(define-data-var verification-expiry-blocks uint u1440)

(define-map Users
  principal
  {
    id: uint,
    role: uint,
    credentials-hash: (optional (buff 32)),
    specialty: (optional (string-utf8 50)),
    location: (optional (string-utf8 100)),
    registered-at: uint,
    verified: bool,
    verification-code: (optional (buff 16)),
    verification-timestamp: (optional uint)
  }
)

(define-map UsersById
  uint
  principal
)

(define-map DoctorSpecialties
  { doctor: principal, specialty: (string-utf8 50) }
  bool
)

(define-map VerificationRequests
  principal
  {
    code: (buff 16),
    timestamp: uint,
    expires-at: uint
  }
)

(define-read-only (get-user (user principal))
  (map-get? Users user)
)

(define-read-only (get-user-by-id (id uint))
  (match (map-get? UsersById id)
    user-principal (get-user user-principal)
    none
  )
)

(define-read-only (is-user-registered (user principal))
  (is-some (map-get? Users user))
)

(define-read-only (is-doctor-verified (user principal))
  (match (get-user user)
    user-data
      (and (is-eq (get role user-data) ROLE-DOCTOR) (get verified user-data))
    false
  )
)

(define-read-only (get-user-count)
  (ok (var-get next-user-id))
)

(define-private (validate-credentials-hash (hash (buff 32)))
  (if (is-eq (len hash) u32)
      (ok true)
      (err ERR-INVALID-CREDENTIALS-HASH))
)

(define-private (validate-specialty (spec (string-utf8 50)))
  (if (and (> (len spec) u0) (<= (len spec) u50))
      (ok true)
      (err ERR-INVALID-SPECIALTY))
)

(define-private (validate-location (loc (string-utf8 100)))
  (if (and (> (len loc) u0) (<= (len loc) u100))
      (ok true)
      (err ERR-INVALID-LOCATION))
)

(define-private (validate-role (role uint))
  (if (or (is-eq role ROLE-PATIENT) (is-eq role ROLE-DOCTOR) (is-eq role ROLE-ADMIN))
      (ok true)
      (err ERR-INVALID-ROLE))
)

(define-private (validate-verification-code (code (buff 16)))
  (if (is-eq (len code) u16)
      (ok true)
      (err ERR-INVALID-VERIFICATION-CODE))
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
      (ok true)
      (err ERR-INVALID-TIMESTAMP))
)

(define-private (is-verified-authority (caller principal))
  (match (var-get authority-contract)
    auth (is-eq caller auth)
    false
  )
)

(define-public (set-authority-contract (contract-principal principal))
  (begin
    (asserts! (is-eq tx-sender 'SP000000000000000000002Q6VF78) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-none (var-get authority-contract)) (err u113))
    (var-set authority-contract (some contract-principal))
    (ok true)
  )
)

(define-public (set-max-users (new-max uint))
  (begin
    (asserts! (is-verified-authority tx-sender) (err ERR-NOT-AUTHORIZED))
    (asserts! (> new-max u0) (err u114))
    (var-set max-users new-max)
    (ok true)
  )
)

(define-public (set-registration-fee (new-fee uint))
  (begin
    (asserts! (is-verified-authority tx-sender) (err ERR-NOT-AUTHORIZED))
    (asserts! (>= new-fee u0) (err ERR-INVALID-UPDATE-PARAM))
    (var-set registration-fee new-fee)
    (ok true)
  )
)

(define-public (set-verification-expiry (blocks uint))
  (begin
    (asserts! (is-verified-authority tx-sender) (err ERR-NOT-AUTHORIZED))
    (asserts! (> blocks u0) (err ERR-INVALID-UPDATE-PARAM))
    (var-set verification-expiry-blocks blocks)
    (ok true)
  )
)

(define-public (register-patient)
  (let (
        (caller tx-sender)
        (next-id (var-get next-user-id))
        (current-max (var-get max-users))
      )
    (asserts! (< next-id current-max) (err ERR-MAX-USERS-EXCEEDED))
    (asserts! (is-none (map-get? Users caller)) (err ERR-ALREADY-REGISTERED))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-SET))
    (let ((authority (unwrap-panic (var-get authority-contract))))
      (try! (stx-transfer? (var-get registration-fee) caller authority))
    )
    (map-set Users caller
      {
        id: next-id,
        role: ROLE-PATIENT,
        credentials-hash: none,
        specialty: none,
        location: none,
        registered-at: block-height,
        verified: true,
        verification-code: none,
        verification-timestamp: none
      }
    )
    (map-set UsersById next-id caller)
    (var-set next-user-id (+ next-id u1))
    (print { event: "patient-registered", user: caller, id: next-id })
    (ok next-id)
  )
)

(define-public (register-doctor
  (credentials-hash (buff 32))
  (specialty (string-utf8 50))
  (location (string-utf8 100))
)
  (let (
        (caller tx-sender)
        (next-id (var-get next-user-id))
        (current-max (var-get max-users))
      )
    (asserts! (< next-id current-max) (err ERR-MAX-USERS-EXCEEDED))
    (asserts! (is-none (map-get? Users caller)) (err ERR-ALREADY-REGISTERED))
    (try! (validate-credentials-hash credentials-hash))
    (try! (validate-specialty specialty))
    (try! (validate-location location))
    (asserts! (is-some (var-get authority-contract)) (err ERR-AUTHORITY-NOT-SET))
    (let ((authority (unwrap-panic (var-get authority-contract))))
      (try! (stx-transfer? (var-get registration-fee) caller authority))
    )
    (map-set Users caller
      {
        id: next-id,
        role: ROLE_DOCTOR,
        credentials-hash: (some credentials-hash),
        specialty: (some specialty),
        location: (some location),
        registered-at: block-height,
        verified: false,
        verification-code: none,
        verification-timestamp: none
      }
    )
    (map-set UsersById next-id caller)
    (map-insert DoctorSpecialties { doctor: caller, specialty: specialty } true)
    (var-set next-user-id (+ next-id u1))
    (print { event: "doctor-registered", user: caller, id: next-id })
    (ok next-id)
  )
)

(define-public (request-verification (code (buff 16)) (timestamp uint))
  (let ((caller tx-sender)
        (user-data (unwrap! (map-get? Users caller) (err ERR-ALREADY-REGISTERED)))
      )
    (asserts! (is-eq (get role user-data) ROLE-DOCTOR) (err ERR-NOT-AUTHORIZED))
    (asserts! (not (get verified user-data)) (err ERR-DOCTOR-NOT-VERIFIED))
    (try! (validate-verification-code code))
    (try! (validate-timestamp timestamp))
    (let (
          (expires-at (+ timestamp (var-get verification-expiry-blocks)))
          (req { code: code, timestamp: timestamp, expires-at: expires-at })
        )
      (map-set VerificationRequests caller req)
      (map-set Users caller (merge user-data { verification-code: (some code), verification-timestamp: (some timestamp) }))
      (print { event: "verification-requested", user: caller })
      (ok true)
    )
  )
)

(define-public (verify-doctor (user principal) (code (buff 16)))
  (begin
    (asserts! (is-verified-authority tx-sender) (err ERR-NOT-AUTHORIZED))
    (let (
          (user-data (unwrap! (map-get? Users user) (err ERR-ALREADY-REGISTERED)))
          (req (unwrap! (map-get? VerificationRequests user) (err ERR-INVALID-VERIFICATION-CODE)))
        )
      (asserts! (is-eq (get code req) code) (err ERR-INVALID-VERIFICATION-CODE))
      (asserts! (<= block-height (get expires-at req)) (err ERR-VERIFICATION-EXPIRED))
      (asserts! (is-eq (get role user-data) ROLE-DOCTOR) (err ERR-NOT-AUTHORIZED))
      (asserts! (not (get verified user-data)) (err ERR-DOCTOR-NOT-VERIFIED))
      (map-set Users user (merge user-data { verified: true }))
      (map-delete VerificationRequests user)
      (print { event: "doctor-verified", user: user })
      (ok true)
    )
  )
)

(define-public (update-user-location (new-location (string-utf8 100)))
  (let ((caller tx-sender)
        (user-data (unwrap! (map-get? Users caller) (err ERR-ALREADY-REGISTERED))))
    (try! (validate-location new-location))
    (map-set Users caller (merge user-data { location: (some new-location) }))
    (print { event: "location-updated", user: caller })
    (ok true)
  )
)

(define-public (update-user-specialty (new-specialty (string-utf8 50)))
  (let ((caller tx-sender)
        (user-data (unwrap! (map-get? Users caller) (err ERR-ALREADY-REGISTERED))))
    (asserts! (is-eq (get role user-data) ROLE-DOCTOR) (err ERR-NOT-AUTHORIZED))
    (try! (validate-specialty new-specialty))
    (map-set Users caller (merge user-data { specialty: (some new-specialty) }))
    (map-insert DoctorSpecialties { doctor: caller, specialty: new-specialty } true)
    (print { event: "specialty-updated", user: caller })
    (ok true)
  )
)