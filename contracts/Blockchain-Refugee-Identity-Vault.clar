(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-unauthorized (err u103))

(define-data-var admin principal contract-owner)

(define-map refugees
    { id: uint }
    {
        name: (string-ascii 50),
        dob: uint,
        nationality: (string-ascii 30),
        status: (string-ascii 20),
        documents: (list 10 (string-utf8 256)),
        verified: bool,
        timestamp: uint,
        location: (string-ascii 50),
    }
)

(define-map authorized-verifiers
    { verifier: principal }
    { active: bool }
)

(define-map document-access-log
    {
        refugee-id: uint,
        accessor: principal,
    }
    { last-access: uint }
)

(define-public (add-refugee
        (id uint)
        (name (string-ascii 50))
        (dob uint)
        (nationality (string-ascii 30))
        (status (string-ascii 20))
        (location (string-ascii 50))
    )
    (let (
            (current-height burn-block-height)
            (empty-docs (list))
        )
        (asserts! (is-authorized) err-unauthorized)
        (asserts! (is-none (map-get? refugees { id: id })) err-already-exists)
        (ok (map-set refugees { id: id } {
            name: name,
            dob: dob,
            nationality: nationality,
            status: status,
            documents: empty-docs,
            verified: false,
            timestamp: current-height,
            location: location,
        }))
    )
)

(define-public (add-document
        (refugee-id uint)
        (document (string-utf8 256))
    )
    (let ((current-refugee (unwrap! (map-get? refugees { id: refugee-id }) err-not-found)))
        (asserts! (is-authorized) err-unauthorized)
        (ok (map-set refugees { id: refugee-id }
            (merge current-refugee { documents: (unwrap!
                (as-max-len? (append (get documents current-refugee) document)
                    u10
                )
                err-unauthorized
            ) }
            )))
    )
)

(define-public (verify-refugee (refugee-id uint))
    (let ((current-refugee (unwrap! (map-get? refugees { id: refugee-id }) err-not-found)))
        (asserts! (is-verifier tx-sender) err-unauthorized)
        (ok (map-set refugees { id: refugee-id }
            (merge current-refugee { verified: true })
        ))
    )
)

(define-public (update-location
        (refugee-id uint)
        (new-location (string-ascii 50))
    )
    (let ((current-refugee (unwrap! (map-get? refugees { id: refugee-id }) err-not-found)))
        (asserts! (is-authorized) err-unauthorized)
        (ok (map-set refugees { id: refugee-id }
            (merge current-refugee { location: new-location })
        ))
    )
)

(define-public (add-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) err-owner-only)
        (ok (map-set authorized-verifiers { verifier: verifier } { active: true }))
    )
)

(define-public (remove-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) err-owner-only)
        (ok (map-set authorized-verifiers { verifier: verifier } { active: false }))
    )
)

(define-read-only (get-refugee-info (id uint))
    (map-get? refugees { id: id })
)

(define-read-only (is-verifier (principal principal))
    (default-to false
        (get active (map-get? authorized-verifiers { verifier: principal }))
    )
)

(define-private (is-authorized)
    (or
        (is-eq tx-sender (var-get admin))
        (is-verifier tx-sender)
    )
)

(define-public (log-access (refugee-id uint))
    (let ((current-height burn-block-height))
        (asserts! (is-authorized) err-unauthorized)
        (ok (map-set document-access-log {
            refugee-id: refugee-id,
            accessor: tx-sender,
        } { last-access: current-height }
        ))
    )
)

(define-read-only (get-access-log
        (refugee-id uint)
        (accessor principal)
    )
    (map-get? document-access-log {
        refugee-id: refugee-id,
        accessor: accessor,
    })
)
