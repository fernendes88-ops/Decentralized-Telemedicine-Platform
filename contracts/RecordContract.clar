(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-HASH u101)
(define-constant ERR-INVALID-PATIENT u102)
(define-constant ERR-INVALID-DOCTOR u103)
(define-constant ERR-RECORD-NOT-FOUND u104)
(define-constant ERR-RECORD-EXISTS u105)
(define-constant ERR-INVALID-TIMESTAMP u106)
(define-constant ERR-INVALID-METADATA u107)
(define-constant ERR-ACCESS-DENIED u108)
(define-constant ERR-INVALID-RECORD-TYPE u109)
(define-constant ERR-INVALID-ENCRYPTION-KEY u110)
(define-constant ERR-INVALID-STATUS u111)
(define-constant ERR-INVALID-UPDATE-PARAM u112)
(define-constant ERR-MAX-RECORDS-EXCEEDED u113)
(define-constant ERR-INVALID-VERSION u114)
(define-constant ERR-RECORD-LOCKED u115)
(define-constant ERR-INVALID-SIGNATURE u116)
(define-constant ERR-INVALID-REFERENCE u117)
(define-constant ERR-INVALID-REVISION u118)
(define-constant ERR-REVISION-NOT-FOUND u119)
(define-constant ERR-INVALID-REVISION-HASH u120)

(define-constant RECORD-TYPE-CONSULTATION u1)
(define-constant RECORD-TYPE-PRESCRIPTION u2)
(define-constant RECORD-TYPE-LAB-RESULT u3)
(define-constant RECORD-TYPE-IMAGING u4)
(define-constant RECORD-TYPE-DISCHARGE u5)

(define-constant RECORD-STATUS-ACTIVE u1)
(define-constant RECORD-STATUS-ARCHIVED u2)
(define-constant RECORD-STATUS-DELETED u3)

(define-data-var next-record-id uint u1)
(define-data-var max-records-per-patient uint u1000)
(define-data-var protocol-version uint u1)

(define-map Records
  uint
  {
    patient: principal,
    doctor: principal,
    record-type: uint,
    record-hash: (buff 32),
    encryption-key-hash: (buff 32),
    timestamp: uint,
    status: uint,
    metadata: (string-utf8 256),
    version: uint,
    revision-count: uint,
    locked: bool
  }
)

(define-map RecordRevisions
  { record-id: uint, revision-id: uint }
  {
    record-hash: (buff 32),
    encryption-key-hash: (buff 32),
    timestamp: uint,
    editor: principal,
    change-note: (string-utf8 128)
  }
)

(define-map PatientRecordIndex
  { patient: principal, record-id: uint }
  bool
)

(define-map DoctorRecordIndex
  { doctor: principal, record-id: uint }
  bool
)

(define-map RecordAccessLog
  { record-id: uint, accessor: principal }
  { timestamp: uint, access-type: (string-utf8 32) }
)

(define-read-only (get-record (record-id uint))
  (map-get? Records record-id)
)

(define-read-only (get-record-revision (record-id uint) (revision-id uint))
  (map-get? RecordRevisions { record-id: record-id, revision-id: revision-id })
)

(define-read-only (get-patient-records-count (patient principal))
  (let (
    (count (fold check-patient-record-range
      (list u1 u2 u3 u4 u5 u6 u7 u8 u9 u10)
      u0))
  )
    (ok count)
  )
)

(define-private (check-patient-record-range (id uint) (acc uint))
  (if (default-to false (map-get? PatientRecordIndex { patient: tx-sender, record-id: id }))
    (+ acc u1)
    acc
  )
)

(define-read-only (is-record-active (record-id uint))
  (match (map-get? Records record-id)
    record (is-eq (get status record) RECORD-STATUS-ACTIVE)
    false
  )
)

(define-read-only (is-record-locked (record-id uint))
  (match (map-get? Records record-id)
    record (get locked record)
    false
  )
)

(define-read-only (validate-record-type (record-type uint))
  (or
    (is-eq record-type RECORD-TYPE-CONSULTATION)
    (is-eq record-type RECORD-TYPE-PRESCRIPTION)
    (is-eq record-type RECORD-TYPE-LAB-RESULT)
    (is-eq record-type RECORD-TYPE-IMAGING)
    (is-eq record-type RECORD-TYPE-DISCHARGE)
  )
)

(define-read-only (validate-record-hash (hash (buff 32)))
  (> (len hash) u0)
)

(define-read-only (validate-encryption-key-hash (hash (buff 32)))
  (> (len hash) u0)
)

(define-read-only (validate-metadata (metadata (string-utf8 256)))
  (and (> (len metadata) u0) (<= (len metadata) u256))
)

(define-read-only (validate-change-note (note (string-utf8 128)))
  (<= (len note) u128)
)

(define-read-only (validate-principal-not-zero (p principal))
  (not (is-eq p 'SP000000000000000000002Q6VF78))
)

(define-read-only (validate-record-status (status uint))
  (or
    (is-eq status RECORD-STATUS-ACTIVE)
    (is-eq status RECORD-STATUS-ARCHIVED)
    (is-eq status RECORD-STATUS-DELETED)
  )
)

(define-public (store-record
  (patient principal)
  (record-type uint)
  (record-hash (buff 32))
  (encryption-key-hash (buff 32))
  (metadata (string-utf8 256))
)
  (let (
    (record-id (var-get next-record-id))
    (caller tx-sender)
    (patient-record-count (fold check-patient-record-range
      (list u1 u2 u3 u4 u5 u6 u7 u8 u9 u10)
      u0))
  )
    (asserts! (validate-principal-not-zero patient) (err ERR-INVALID-PATIENT))
    (asserts! (validate-principal-not-zero caller) (err ERR-INVALID-DOCTOR))
    (asserts! (validate-record-type record-type) (err ERR-INVALID-RECORD-TYPE))
    (asserts! (validate-record-hash record-hash) (err ERR-INVALID-HASH))
    (asserts! (validate-encryption-key-hash encryption-key-hash) (err ERR-INVALID-ENCRYPTION-KEY))
    (asserts! (validate-metadata metadata) (err ERR-INVALID-METADATA))
    (asserts! (< patient-record-count (var-get max-records-per-patient)) (err ERR-MAX-RECORDS-EXCEEDED))
    (map-set Records record-id
      {
        patient: patient,
        doctor: caller,
        record-type: record-type,
        record-hash: record-hash,
        encryption-key-hash: encryption-key-hash,
        timestamp: block-height,
        status: RECORD-STATUS-ACTIVE,
        metadata: metadata,
        version: u1,
        revision-count: u0,
        locked: false
      }
    )
    (map-set PatientRecordIndex { patient: patient, record-id: record-id } true)
    (map-set DoctorRecordIndex { doctor: caller, record-id: record-id } true)
    (var-set next-record-id (+ record-id u1))
    (print { event: "record-stored", record-id: record-id, patient: patient })
    (ok record-id)
  )
)

(define-public (update-record-hash
  (record-id uint)
  (new-record-hash (buff 32))
  (new-encryption-key-hash (buff 32))
  (change-note (string-utf8 128))
)
  (let (
    (record (unwrap! (map-get? Records record-id) (err ERR-RECORD-NOT-FOUND)))
    (caller tx-sender)
    (current-revision (get revision-count record))
    (new-revision (+ current-revision u1))
  )
    (asserts! (is-eq (get doctor record) caller) (err ERR-ACCESS-DENIED))
    (asserts! (not (get locked record)) (err ERR-RECORD-LOCKED))
    (asserts! (validate-record-hash new-record-hash) (err ERR-INVALID-HASH))
    (asserts! (validate-encryption-key-hash new-encryption-key-hash) (err ERR-INVALID-ENCRYPTION-KEY))
    (asserts! (validate-change-note change-note) (err ERR-INVALID-UPDATE-PARAM))
    (map-set RecordRevisions
      { record-id: record-id, revision-id: new-revision }
      {
        record-hash: new-record-hash,
        encryption-key-hash: new-encryption-key-hash,
        timestamp: block-height,
        editor: caller,
        change-note: change-note
      }
    )
    (map-set Records record-id
      (merge record
        {
          record-hash: new-record-hash,
          encryption-key-hash: new-encryption-key-hash,
          version: (+ (get version record) u1),
          revision-count: new-revision
        }
      )
    )
    (print { event: "record-updated", record-id: record-id, revision: new-revision })
    (ok new-revision)
  )
)

(define-public (lock-record (record-id uint))
  (let (
    (record (unwrap! (map-get? Records record-id) (err ERR-RECORD-NOT-FOUND)))
    (caller tx-sender)
  )
    (asserts! (or (is-eq (get patient record) caller) (is-eq (get doctor record) caller)) (err ERR-ACCESS-DENIED))
    (asserts! (not (get locked record)) (err ERR-RECORD-LOCKED))
    (map-set Records record-id (merge record { locked: true }))
    (print { event: "record-locked", record-id: record-id })
    (ok true)
  )
)

(define-public (archive-record (record-id uint))
  (let (
    (record (unwrap! (map-get? Records record-id) (err ERR-RECORD-NOT-FOUND)))
    (caller tx-sender)
  )
    (asserts! (is-eq (get patient record) caller) (err ERR-ACCESS-DENIED))
    (asserts! (is-eq (get status record) RECORD-STATUS-ACTIVE) (err ERR-INVALID-STATUS))
    (map-set Records record-id (merge record { status: RECORD-STATUS-ARCHIVED }))
    (print { event: "record-archived", record-id: record-id })
    (ok true)
  )
)

(define-public (log-access (record-id uint) (access-type (string-utf8 32)))
  (begin
    (map-set RecordAccessLog
      { record-id: record-id, accessor: tx-sender }
      { timestamp: block-height, access-type: access-type }
    )
    (ok true)
  )
)

(define-public (get-latest-revision-id (record-id uint))
  (match (map-get? Records record-id)
    record (ok (get revision-count record))
    (err ERR-RECORD-NOT-FOUND)
  )
)