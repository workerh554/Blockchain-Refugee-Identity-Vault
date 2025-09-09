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
(define-constant err-invalid-contact (err u104))

(define-map emergency-contacts
    {
        refugee-id: uint,
        contact-id: uint,
    }
    {
        name: (string-ascii 50),
        relationship: (string-ascii 30),
        phone: (string-ascii 20),
        email: (string-ascii 100),
        location: (string-ascii 50),
        priority: uint,
        verified: bool,
        timestamp: uint,
    }
)

(define-map contact-counter
    { refugee-id: uint }
    { count: uint }
)

(define-map authorized-responders
    { responder: principal }
    { active: bool }
)

(define-public (add-emergency-contact
        (refugee-id uint)
        (name (string-ascii 50))
        (relationship (string-ascii 30))
        (phone (string-ascii 20))
        (email (string-ascii 100))
        (location (string-ascii 50))
        (priority uint)
    )
    (let (
            (current-count (default-to u0
                (get count (map-get? contact-counter { refugee-id: refugee-id }))
            ))
            (new-contact-id (+ current-count u1))
            (current-height burn-block-height)
        )
        (asserts! (is-authorized-user refugee-id) err-unauthorized)
        (asserts! (<= priority u5) err-invalid-contact)
        (asserts!
            (is-none (map-get? emergency-contacts {
                refugee-id: refugee-id,
                contact-id: new-contact-id,
            }))
            err-already-exists
        )
        (map-set contact-counter { refugee-id: refugee-id } { count: new-contact-id })
        (ok (map-set emergency-contacts {
            refugee-id: refugee-id,
            contact-id: new-contact-id,
        } {
            name: name,
            relationship: relationship,
            phone: phone,
            email: email,
            location: location,
            priority: priority,
            verified: false,
            timestamp: current-height,
        }))
    )
)

(define-public (verify-emergency-contact
        (refugee-id uint)
        (contact-id uint)
    )
    (let ((current-contact (unwrap!
            (map-get? emergency-contacts {
                refugee-id: refugee-id,
                contact-id: contact-id,
            })
            err-not-found
        )))
        (asserts! (is-responder tx-sender) err-unauthorized)
        (ok (map-set emergency-contacts {
            refugee-id: refugee-id,
            contact-id: contact-id,
        }
            (merge current-contact { verified: true })
        ))
    )
)

(define-public (add-responder (responder principal))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) err-owner-only)
        (ok (map-set authorized-responders { responder: responder } { active: true }))
    )
)

(define-public (remove-responder (responder principal))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) err-owner-only)
        (ok (map-set authorized-responders { responder: responder } { active: false }))
    )
)

(define-read-only (get-emergency-contact
        (refugee-id uint)
        (contact-id uint)
    )
    (map-get? emergency-contacts {
        refugee-id: refugee-id,
        contact-id: contact-id,
    })
)

(define-read-only (get-contact-count (refugee-id uint))
    (default-to u0
        (get count (map-get? contact-counter { refugee-id: refugee-id }))
    )
)

(define-read-only (is-responder (principal principal))
    (default-to false
        (get active (map-get? authorized-responders { responder: principal }))
    )
)

(define-private (is-authorized-user (refugee-id uint))
    (or
        (is-eq tx-sender (var-get admin))
        (is-responder tx-sender)
    )
)
(define-constant err-expired (err u105))
(define-constant err-invalid-date (err u106))

(define-map document-registry
    {
        refugee-id: uint,
        document-hash: (buff 32),
    }
    {
        document-type: (string-ascii 30),
        issue-date: uint,
        expiry-date: uint,
        issuing-authority: (string-ascii 50),
        status: (string-ascii 20),
        renewal-required: bool,
        last-updated: uint,
    }
)

(define-map renewal-requests
    {
        refugee-id: uint,
        document-hash: (buff 32),
        request-id: uint,
    }
    {
        new-document-hash: (buff 32),
        new-expiry-date: uint,
        requested-by: principal,
        approved: bool,
        processed: bool,
        timestamp: uint,
    }
)

(define-map request-counter
    { refugee-id: uint }
    { count: uint }
)

(define-map authorized-issuers
    { issuer: principal }
    { active: bool }
)

(define-public (register-document
        (refugee-id uint)
        (document-hash (buff 32))
        (document-type (string-ascii 30))
        (issue-date uint)
        (expiry-date uint)
        (issuing-authority (string-ascii 50))
    )
    (let ((current-height burn-block-height))
        (asserts! (is-authorized-issuer) err-unauthorized)
        (asserts! (> expiry-date issue-date) err-invalid-date)
        (asserts!
            (is-none (map-get? document-registry {
                refugee-id: refugee-id,
                document-hash: document-hash,
            }))
            err-already-exists
        )
        (ok (map-set document-registry {
            refugee-id: refugee-id,
            document-hash: document-hash,
        } {
            document-type: document-type,
            issue-date: issue-date,
            expiry-date: expiry-date,
            issuing-authority: issuing-authority,
            status: "active",
            renewal-required: false,
            last-updated: current-height,
        }))
    )
)

(define-public (request-renewal
        (refugee-id uint)
        (old-document-hash (buff 32))
        (new-document-hash (buff 32))
        (new-expiry-date uint)
    )
    (let (
            (current-count (default-to u0
                (get count (map-get? request-counter { refugee-id: refugee-id }))
            ))
            (new-request-id (+ current-count u1))
            (current-height burn-block-height)
            (document-exists (unwrap!
                (map-get? document-registry {
                    refugee-id: refugee-id,
                    document-hash: old-document-hash,
                })
                err-not-found
            ))
        )
        (asserts! (is-authorized-issuer) err-unauthorized)
        (asserts! (> new-expiry-date current-height) err-invalid-date)
        (map-set request-counter { refugee-id: refugee-id } { count: new-request-id })
        (ok (map-set renewal-requests {
            refugee-id: refugee-id,
            document-hash: old-document-hash,
            request-id: new-request-id,
        } {
            new-document-hash: new-document-hash,
            new-expiry-date: new-expiry-date,
            requested-by: tx-sender,
            approved: false,
            processed: false,
            timestamp: current-height,
        }))
    )
)

(define-public (approve-renewal
        (refugee-id uint)
        (old-document-hash (buff 32))
        (request-id uint)
    )
    (let (
            (renewal-request (unwrap!
                (map-get? renewal-requests {
                    refugee-id: refugee-id,
                    document-hash: old-document-hash,
                    request-id: request-id,
                })
                err-not-found
            ))
            (current-document (unwrap!
                (map-get? document-registry {
                    refugee-id: refugee-id,
                    document-hash: old-document-hash,
                })
                err-not-found
            ))
            (current-height burn-block-height)
        )
        (asserts! (is-eq tx-sender (var-get admin)) err-owner-only)
        (asserts! (not (get processed renewal-request)) err-already-exists)
        (map-set renewal-requests {
            refugee-id: refugee-id,
            document-hash: old-document-hash,
            request-id: request-id,
        }
            (merge renewal-request {
                approved: true,
                processed: true,
            })
        )
        (map-set document-registry {
            refugee-id: refugee-id,
            document-hash: old-document-hash,
        }
            (merge current-document {
                status: "expired",
                last-updated: current-height,
            })
        )
        (ok (map-set document-registry {
            refugee-id: refugee-id,
            document-hash: (get new-document-hash renewal-request),
        } {
            document-type: (get document-type current-document),
            issue-date: current-height,
            expiry-date: (get new-expiry-date renewal-request),
            issuing-authority: (get issuing-authority current-document),
            status: "active",
            renewal-required: false,
            last-updated: current-height,
        }))
    )
)

(define-public (mark-renewal-required
        (refugee-id uint)
        (document-hash (buff 32))
    )
    (let ((current-document (unwrap!
            (map-get? document-registry {
                refugee-id: refugee-id,
                document-hash: document-hash,
            })
            err-not-found
        )))
        (asserts! (is-authorized-issuer) err-unauthorized)
        (ok (map-set document-registry {
            refugee-id: refugee-id,
            document-hash: document-hash,
        }
            (merge current-document { renewal-required: true })
        ))
    )
)

(define-public (add-issuer (issuer principal))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) err-owner-only)
        (ok (map-set authorized-issuers { issuer: issuer } { active: true }))
    )
)

(define-public (remove-issuer (issuer principal))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) err-owner-only)
        (ok (map-set authorized-issuers { issuer: issuer } { active: false }))
    )
)

(define-read-only (get-document-info
        (refugee-id uint)
        (document-hash (buff 32))
    )
    (map-get? document-registry {
        refugee-id: refugee-id,
        document-hash: document-hash,
    })
)

(define-read-only (is-document-expired
        (refugee-id uint)
        (document-hash (buff 32))
    )
    (let ((document-info (map-get? document-registry {
            refugee-id: refugee-id,
            document-hash: document-hash,
        })))
        (match document-info
            doc (< (get expiry-date doc) burn-block-height)
            false
        )
    )
)

(define-read-only (get-renewal-request
        (refugee-id uint)
        (document-hash (buff 32))
        (request-id uint)
    )
    (map-get? renewal-requests {
        refugee-id: refugee-id,
        document-hash: document-hash,
        request-id: request-id,
    })
)

(define-read-only (is-issuer (principal principal))
    (default-to false
        (get active (map-get? authorized-issuers { issuer: principal }))
    )
)

(define-private (is-authorized-issuer)
    (or
        (is-eq tx-sender (var-get admin))
        (is-issuer tx-sender)
    )
)
(define-constant err-insufficient-approvals (err u107))
(define-constant err-already-approved (err u108))
(define-constant err-approval-not-found (err u109))

(define-data-var min-approvals-required uint u2)

(define-map pending-documents
    {
        refugee-id: uint,
        document-hash: (buff 32),
        proposal-id: uint,
    }
    {
        document-type: (string-ascii 30),
        issue-date: uint,
        expiry-date: uint,
        issuing-authority: (string-ascii 50),
        proposer: principal,
        approvals-count: uint,
        executed: bool,
        timestamp: uint,
    }
)

(define-map document-approvals
    {
        refugee-id: uint,
        document-hash: (buff 32),
        proposal-id: uint,
        approver: principal,
    }
    { approved: bool }
)

(define-map proposal-counter
    { refugee-id: uint }
    { count: uint }
)

(define-public (propose-document
        (refugee-id uint)
        (document-hash (buff 32))
        (document-type (string-ascii 30))
        (issue-date uint)
        (expiry-date uint)
        (issuing-authority (string-ascii 50))
    )
    (let (
            (current-count (default-to u0
                (get count (map-get? proposal-counter { refugee-id: refugee-id }))
            ))
            (new-proposal-id (+ current-count u1))
            (current-height burn-block-height)
        )
        (asserts! (is-authorized-issuer) err-unauthorized)
        (asserts! (> expiry-date issue-date) err-invalid-date)
        (asserts!
            (is-none (map-get? pending-documents {
                refugee-id: refugee-id,
                document-hash: document-hash,
                proposal-id: new-proposal-id,
            }))
            err-already-exists
        )
        (map-set proposal-counter { refugee-id: refugee-id } { count: new-proposal-id })
        (ok (map-set pending-documents {
            refugee-id: refugee-id,
            document-hash: document-hash,
            proposal-id: new-proposal-id,
        } {
            document-type: document-type,
            issue-date: issue-date,
            expiry-date: expiry-date,
            issuing-authority: issuing-authority,
            proposer: tx-sender,
            approvals-count: u0,
            executed: false,
            timestamp: current-height,
        }))
    )
)

(define-public (approve-document
        (refugee-id uint)
        (document-hash (buff 32))
        (proposal-id uint)
    )
    (let (
            (pending-doc (unwrap!
                (map-get? pending-documents {
                    refugee-id: refugee-id,
                    document-hash: document-hash,
                    proposal-id: proposal-id,
                })
                err-not-found
            ))
            (existing-approval (map-get? document-approvals {
                refugee-id: refugee-id,
                document-hash: document-hash,
                proposal-id: proposal-id,
                approver: tx-sender,
            }))
        )
        (asserts! (is-authorized-issuer) err-unauthorized)
        (asserts! (not (get executed pending-doc)) err-already-exists)
        (asserts! (is-none existing-approval) err-already-approved)
        (map-set document-approvals {
            refugee-id: refugee-id,
            document-hash: document-hash,
            proposal-id: proposal-id,
            approver: tx-sender,
        } { approved: true }
        )
        (ok (map-set pending-documents {
            refugee-id: refugee-id,
            document-hash: document-hash,
            proposal-id: proposal-id,
        }
            (merge pending-doc { approvals-count: (+ (get approvals-count pending-doc) u1) })
        ))
    )
)

(define-public (execute-document-proposal
        (refugee-id uint)
        (document-hash (buff 32))
        (proposal-id uint)
    )
    (let (
            (pending-doc (unwrap!
                (map-get? pending-documents {
                    refugee-id: refugee-id,
                    document-hash: document-hash,
                    proposal-id: proposal-id,
                })
                err-not-found
            ))
            (current-height burn-block-height)
            (min-required (var-get min-approvals-required))
        )
        (asserts! (is-authorized-issuer) err-unauthorized)
        (asserts! (not (get executed pending-doc)) err-already-exists)
        (asserts! (>= (get approvals-count pending-doc) min-required)
            err-insufficient-approvals
        )
        (map-set pending-documents {
            refugee-id: refugee-id,
            document-hash: document-hash,
            proposal-id: proposal-id,
        }
            (merge pending-doc { executed: true })
        )
        (ok (map-set document-registry {
            refugee-id: refugee-id,
            document-hash: document-hash,
        } {
            document-type: (get document-type pending-doc),
            issue-date: (get issue-date pending-doc),
            expiry-date: (get expiry-date pending-doc),
            issuing-authority: (get issuing-authority pending-doc),
            status: "active",
            renewal-required: false,
            last-updated: current-height,
        }))
    )
)

(define-public (set-approval-threshold (new-threshold uint))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) err-owner-only)
        (asserts! (> new-threshold u0) err-invalid-date)
        (ok (var-set min-approvals-required new-threshold))
    )
)

(define-read-only (get-pending-document
        (refugee-id uint)
        (document-hash (buff 32))
        (proposal-id uint)
    )
    (map-get? pending-documents {
        refugee-id: refugee-id,
        document-hash: document-hash,
        proposal-id: proposal-id,
    })
)

(define-read-only (has-approved
        (refugee-id uint)
        (document-hash (buff 32))
        (proposal-id uint)
        (approver principal)
    )
    (default-to false
        (get approved
            (map-get? document-approvals {
                refugee-id: refugee-id,
                document-hash: document-hash,
                proposal-id: proposal-id,
                approver: approver,
            })
        ))
)

(define-read-only (get-approval-threshold)
    (var-get min-approvals-required)
)
(define-constant err-biometric-exists (err u110))
(define-constant err-biometric-not-found (err u111))
(define-constant err-biometric-mismatch (err u112))
(define-constant err-biometric-expired (err u113))

(define-map biometric-data
    {
        refugee-id: uint,
        biometric-type: (string-ascii 20),
    }
    {
        data-hash: (buff 32),
        registered-at: uint,
        expires-at: uint,
        verified: bool,
        registered-by: principal,
    }
)

(define-map biometric-requirements
    { biometric-type: (string-ascii 20) }
    { required: bool }
)

(define-map authorized-biometric-officers
    { officer: principal }
    { active: bool }
)

(define-public (register-biometric
        (refugee-id uint)
        (biometric-type (string-ascii 20))
        (data-hash (buff 32))
        (validity-period uint)
    )
    (let (
            (current-height burn-block-height)
            (expiry-date (+ current-height validity-period))
        )
        (asserts! (is-biometric-officer tx-sender) err-unauthorized)
        (asserts!
            (is-none (map-get? biometric-data {
                refugee-id: refugee-id,
                biometric-type: biometric-type,
            }))
            err-biometric-exists
        )
        (asserts! (> validity-period u0) err-invalid-date)
        (ok (map-set biometric-data {
            refugee-id: refugee-id,
            biometric-type: biometric-type,
        } {
            data-hash: data-hash,
            registered-at: current-height,
            expires-at: expiry-date,
            verified: false,
            registered-by: tx-sender,
        }))
    )
)

(define-public (verify-biometric
        (refugee-id uint)
        (biometric-type (string-ascii 20))
        (provided-hash (buff 32))
    )
    (let (
            (stored-biometric (unwrap!
                (map-get? biometric-data {
                    refugee-id: refugee-id,
                    biometric-type: biometric-type,
                })
                err-biometric-not-found
            ))
            (current-height burn-block-height)
        )
        (asserts! (is-biometric-officer tx-sender) err-unauthorized)
        (asserts! (< current-height (get expires-at stored-biometric))
            err-biometric-expired
        )
        (asserts! (is-eq (get data-hash stored-biometric) provided-hash)
            err-biometric-mismatch
        )
        (ok (map-set biometric-data {
            refugee-id: refugee-id,
            biometric-type: biometric-type,
        }
            (merge stored-biometric { verified: true })
        ))
    )
)

(define-public (update-biometric
        (refugee-id uint)
        (biometric-type (string-ascii 20))
        (new-data-hash (buff 32))
        (validity-period uint)
    )
    (let (
            (existing-biometric (unwrap!
                (map-get? biometric-data {
                    refugee-id: refugee-id,
                    biometric-type: biometric-type,
                })
                err-biometric-not-found
            ))
            (current-height burn-block-height)
            (expiry-date (+ current-height validity-period))
        )
        (asserts! (is-biometric-officer tx-sender) err-unauthorized)
        (asserts! (> validity-period u0) err-invalid-date)
        (ok (map-set biometric-data {
            refugee-id: refugee-id,
            biometric-type: biometric-type,
        } {
            data-hash: new-data-hash,
            registered-at: current-height,
            expires-at: expiry-date,
            verified: false,
            registered-by: tx-sender,
        }))
    )
)

(define-public (revoke-biometric
        (refugee-id uint)
        (biometric-type (string-ascii 20))
    )
    (let ((existing-biometric (unwrap!
            (map-get? biometric-data {
                refugee-id: refugee-id,
                biometric-type: biometric-type,
            })
            err-biometric-not-found
        )))
        (asserts! (is-eq tx-sender (var-get admin)) err-owner-only)
        (ok (map-delete biometric-data {
            refugee-id: refugee-id,
            biometric-type: biometric-type,
        }))
    )
)

(define-public (set-biometric-requirement
        (biometric-type (string-ascii 20))
        (required bool)
    )
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) err-owner-only)
        (ok (map-set biometric-requirements { biometric-type: biometric-type } { required: required }))
    )
)

(define-public (add-biometric-officer (officer principal))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) err-owner-only)
        (ok (map-set authorized-biometric-officers { officer: officer } { active: true }))
    )
)

(define-public (remove-biometric-officer (officer principal))
    (begin
        (asserts! (is-eq tx-sender (var-get admin)) err-owner-only)
        (ok (map-set authorized-biometric-officers { officer: officer } { active: false }))
    )
)

(define-read-only (get-biometric-info
        (refugee-id uint)
        (biometric-type (string-ascii 20))
    )
    (map-get? biometric-data {
        refugee-id: refugee-id,
        biometric-type: biometric-type,
    })
)

(define-read-only (is-biometric-valid
        (refugee-id uint)
        (biometric-type (string-ascii 20))
    )
    (let ((biometric-info (map-get? biometric-data {
            refugee-id: refugee-id,
            biometric-type: biometric-type,
        })))
        (match biometric-info
            bio (and
                (get verified bio)
                (< burn-block-height (get expires-at bio))
            )
            false
        )
    )
)

(define-read-only (is-biometric-required (biometric-type (string-ascii 20)))
    (default-to false
        (get required
            (map-get? biometric-requirements { biometric-type: biometric-type })
        ))
)

(define-read-only (is-biometric-officer (principal principal))
    (default-to false
        (get active
            (map-get? authorized-biometric-officers { officer: principal })
        ))
)
