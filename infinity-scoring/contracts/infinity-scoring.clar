;; Infinity Scoring - Decentralized Identity Credibility System
;; A privacy-preserving reputation system with credential verification

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-validator (err u101))
(define-constant err-invalid-score (err u102))
(define-constant err-credential-exists (err u103))
(define-constant err-credential-not-found (err u104))
(define-constant err-insufficient-stake (err u105))
(define-constant err-already-validator (err u106))

;; Minimum stake required to become a validator (in microSTX)
(define-constant min-validator-stake u1000000)

;; Maximum credibility score
(define-constant max-score u10000)

;; Time decay factor (blocks)
(define-constant decay-blocks u52560) ;; Approximately 1 year in Bitcoin blocks

;; Data Variables
(define-data-var validator-count uint u0)

;; Data Maps

;; User credibility scores
(define-map user-scores
    principal
    {
        total-score: uint,
        last-updated: uint,
        credential-count: uint
    }
)

;; Validators registry
(define-map validators
    principal
    {
        active: bool,
        stake: uint,
        accuracy-score: uint,
        validations-count: uint,
        joined-at: uint
    }
)

;; Credentials storage (hash-based for privacy)
(define-map credentials
    {user: principal, credential-hash: (buff 32)}
    {
        domain: (string-ascii 50),
        score-weight: uint,
        verified-by: principal,
        verified-at: uint,
        expires-at: uint
    }
)

;; Validator consensus tracking
(define-map credential-verifications
    {credential-hash: (buff 32), validator: principal}
    {verified: bool, timestamp: uint}
)

;; Domain weights for different credential types
(define-map domain-weights
    (string-ascii 50)
    uint
)

;; Read-only functions

(define-read-only (get-user-score (user principal))
    (default-to 
        {total-score: u0, last-updated: u0, credential-count: u0}
        (map-get? user-scores user)
    )
)

(define-read-only (get-validator-info (validator principal))
    (map-get? validators validator)
)

(define-read-only (is-validator (address principal))
    (match (map-get? validators address)
        validator-info (get active validator-info)
        false
    )
)

(define-read-only (get-credential (user principal) (cred-hash (buff 32)))
    (map-get? credentials {user: user, credential-hash: cred-hash})
)

(define-read-only (get-domain-weight (domain (string-ascii 50)))
    (default-to u100 (map-get? domain-weights domain))
)

(define-read-only (calculate-decayed-score (original-score uint) (blocks-passed uint))
    (let
        (
            (decay-factor (/ (* blocks-passed u100) decay-blocks))
        )
        (if (>= decay-factor u100)
            u0
            (/ (* original-score (- u100 decay-factor)) u100)
        )
    )
)

;; Public functions

;; Initialize domain weights (only contract owner)
(define-public (set-domain-weight (domain (string-ascii 50)) (weight uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (asserts! (<= weight u1000) err-invalid-score)
        (ok (map-set domain-weights domain weight))
    )
)

;; Register as a validator with stake
(define-public (register-validator)
    (let
        (
            (existing-validator (map-get? validators tx-sender))
        )
        (asserts! (is-none existing-validator) err-already-validator)
        (try! (stx-transfer? min-validator-stake tx-sender (as-contract tx-sender)))
        (map-set validators tx-sender {
            active: true,
            stake: min-validator-stake,
            accuracy-score: u100,
            validations-count: u0,
            joined-at: block-height
        })
        (var-set validator-count (+ (var-get validator-count) u1))
        (ok true)
    )
)

;; Add or update a credential (validator only)
(define-public (add-credential 
    (user principal) 
    (cred-hash (buff 32)) 
    (domain (string-ascii 50))
    (score-weight uint)
    (expiry-blocks uint))
    (let
        (
            (validator-info (unwrap! (map-get? validators tx-sender) err-not-validator))
            (existing-cred (map-get? credentials {user: user, credential-hash: cred-hash}))
        )
        (asserts! (get active validator-info) err-not-validator)
        (asserts! (<= score-weight u1000) err-invalid-score)
        (asserts! (is-none existing-cred) err-credential-exists)
        
        ;; Store credential
        (map-set credentials 
            {user: user, credential-hash: cred-hash}
            {
                domain: domain,
                score-weight: score-weight,
                verified-by: tx-sender,
                verified-at: block-height,
                expires-at: (+ block-height expiry-blocks)
            }
        )
        
        ;; Record verification
        (map-set credential-verifications
            {credential-hash: cred-hash, validator: tx-sender}
            {verified: true, timestamp: block-height}
        )
        
        ;; Update validator stats
        (map-set validators tx-sender
            (merge validator-info {validations-count: (+ (get validations-count validator-info) u1)})
        )
        
        ;; Update user score
        (update-user-score user)
    )
)

;; Calculate and update user's total credibility score
(define-public (update-user-score (user principal))
    (let
        (
            (current-score-data (get-user-score user))
            (new-credential-count (+ (get credential-count current-score-data) u1))
        )
        (map-set user-scores user {
            total-score: (get total-score current-score-data),
            last-updated: block-height,
            credential-count: new-credential-count
        })
        (ok true)
    )
)

;; Revoke a credential (validator only)
(define-public (revoke-credential (user principal) (cred-hash (buff 32)))
    (let
        (
            (validator-info (unwrap! (map-get? validators tx-sender) err-not-validator))
            (credential (unwrap! (map-get? credentials {user: user, credential-hash: cred-hash}) err-credential-not-found))
        )
        (asserts! (get active validator-info) err-not-validator)
        (asserts! (is-eq (get verified-by credential) tx-sender) err-not-validator)
        
        (map-delete credentials {user: user, credential-hash: cred-hash})
        (ok true)
    )
)

;; Deactivate validator (owner only)
(define-public (deactivate-validator (validator principal))
    (let
        (
            (validator-info (unwrap! (map-get? validators validator) err-not-validator))
        )
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (map-set validators validator
            (merge validator-info {active: false})
        )
        (ok true)
    )
)

;; Withdraw validator stake (if inactive)
(define-public (withdraw-stake)
    (let
        (
            (validator-info (unwrap! (map-get? validators tx-sender) err-not-validator))
        )
        (asserts! (not (get active validator-info)) err-not-validator)
        (try! (as-contract (stx-transfer? (get stake validator-info) tx-sender tx-sender)))
        (map-delete validators tx-sender)
        (ok true)
    )
)

;; Initialize contract with default domain weights
(begin
    (map-set domain-weights "professional" u300)
    (map-set domain-weights "social" u200)
    (map-set domain-weights "financial" u400)
    (map-set domain-weights "community" u100)
)