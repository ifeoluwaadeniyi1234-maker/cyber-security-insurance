
;; title: cyber-insurance
;; version: 1.0.0
;; summary: Digital risk coverage system with security assessment and incident response
;; description: A smart contract for cyber security insurance providing coverage, 
;;              security assessments, incident reporting, and breach recovery coordination

;; constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_NOT_AUTHORIZED (err u401))
(define-constant ERR_ALREADY_EXISTS (err u402))
(define-constant ERR_NOT_FOUND (err u404))
(define-constant ERR_INVALID_AMOUNT (err u400))
(define-constant ERR_INSUFFICIENT_COVERAGE (err u403))
(define-constant ERR_INVALID_ASSESSMENT (err u405))
(define-constant ERR_CLAIM_REJECTED (err u406))

;; Security risk levels
(define-constant RISK_LOW u1)
(define-constant RISK_MEDIUM u2)
(define-constant RISK_HIGH u3)
(define-constant RISK_CRITICAL u4)

;; Policy status constants
(define-constant STATUS_ACTIVE u1)
(define-constant STATUS_SUSPENDED u2)
(define-constant STATUS_EXPIRED u3)

;; Claim status constants
(define-constant CLAIM_PENDING u1)
(define-constant CLAIM_APPROVED u2)
(define-constant CLAIM_REJECTED u3)
(define-constant CLAIM_PAID u4)

;; data vars
(define-data-var policy-counter uint u0)
(define-data-var assessment-counter uint u0)
(define-data-var claim-counter uint u0)
(define-data-var total-premiums-collected uint u0)
(define-data-var total-claims-paid uint u0)

;; data maps
;; Insurance policies map
(define-map policies
  { policy-id: uint }
  {
    business-owner: principal,
    coverage-amount: uint,
    premium-amount: uint,
    risk-level: uint,
    status: uint,
    created-at: uint,
    expires-at: uint
  }
)

;; Security assessments map
(define-map security-assessments
  { assessment-id: uint }
  {
    policy-id: uint,
    business-owner: principal,
    risk-score: uint,
    vulnerabilities-count: uint,
    assessment-date: uint,
    assessor: principal
  }
)

;; Security incidents and claims map
(define-map incident-claims
  { claim-id: uint }
  {
    policy-id: uint,
    claimant: principal,
    incident-type: (string-ascii 64),
    damage-amount: uint,
    status: uint,
    filed-at: uint,
    processed-at: (optional uint)
  }
)

;; Recovery coordination map
(define-map recovery-plans
  { claim-id: uint }
  {
    recovery-steps: (list 10 (string-ascii 128)),
    coordinator: principal,
    completion-status: uint,
    estimated-timeline: uint
  }
)

;; public functions

;; Create new insurance policy
(define-public (create-policy (coverage-amount uint) (premium-amount uint) (duration uint))
  (let
    (
      (policy-id (+ (var-get policy-counter) u1))
      (expires-at (+ stacks-block-height duration))
    )
    (begin
      ;; Validate inputs
      (asserts! (> coverage-amount u0) ERR_INVALID_AMOUNT)
      (asserts! (> premium-amount u0) ERR_INVALID_AMOUNT)
      (asserts! (> duration u0) ERR_INVALID_AMOUNT)
      
      ;; Store policy
      (map-set policies
        { policy-id: policy-id }
        {
          business-owner: tx-sender,
          coverage-amount: coverage-amount,
          premium-amount: premium-amount,
          risk-level: RISK_MEDIUM, ;; Default to medium, updated after assessment
          status: STATUS_ACTIVE,
          created-at: stacks-block-height,
          expires-at: expires-at
        }
      )
      
      ;; Update counter and total premiums
      (var-set policy-counter policy-id)
      (var-set total-premiums-collected (+ (var-get total-premiums-collected) premium-amount))
      
      (ok policy-id)
    )
  )
)

;; Conduct security assessment
(define-public (conduct-security-assessment (policy-id uint) (risk-score uint) (vulnerabilities-count uint))
  (let
    (
      (assessment-id (+ (var-get assessment-counter) u1))
      (policy (unwrap! (map-get? policies { policy-id: policy-id }) ERR_NOT_FOUND))
    )
    (begin
      ;; Only contract owner or authorized assessors can conduct assessments
      (asserts! (or (is-eq tx-sender CONTRACT_OWNER) 
                   (is-eq tx-sender (get business-owner policy))) ERR_NOT_AUTHORIZED)
      
      ;; Validate risk score (1-100)
      (asserts! (and (>= risk-score u1) (<= risk-score u100)) ERR_INVALID_ASSESSMENT)
      
      ;; Store assessment
      (map-set security-assessments
        { assessment-id: assessment-id }
        {
          policy-id: policy-id,
          business-owner: (get business-owner policy),
          risk-score: risk-score,
          vulnerabilities-count: vulnerabilities-count,
          assessment-date: stacks-block-height,
          assessor: tx-sender
        }
      )
      
      ;; Update policy risk level based on assessment
      (map-set policies
        { policy-id: policy-id }
        (merge policy {
          risk-level: (calculate-risk-level risk-score vulnerabilities-count)
        })
      )
      
      ;; Update counter
      (var-set assessment-counter assessment-id)
      
      (ok assessment-id)
    )
  )
)

;; File incident claim
(define-public (file-incident-claim (policy-id uint) (incident-type (string-ascii 64)) (damage-amount uint))
  (let
    (
      (claim-id (+ (var-get claim-counter) u1))
      (policy (unwrap! (map-get? policies { policy-id: policy-id }) ERR_NOT_FOUND))
    )
    (begin
      ;; Verify claimant is policy owner
      (asserts! (is-eq tx-sender (get business-owner policy)) ERR_NOT_AUTHORIZED)
      
      ;; Verify policy is active
      (asserts! (is-eq (get status policy) STATUS_ACTIVE) ERR_NOT_AUTHORIZED)
      (asserts! (< stacks-block-height (get expires-at policy)) ERR_NOT_AUTHORIZED)
      
      ;; Validate damage amount
      (asserts! (> damage-amount u0) ERR_INVALID_AMOUNT)
      
      ;; Store claim
      (map-set incident-claims
        { claim-id: claim-id }
        {
          policy-id: policy-id,
          claimant: tx-sender,
          incident-type: incident-type,
          damage-amount: damage-amount,
          status: CLAIM_PENDING,
          filed-at: stacks-block-height,
          processed-at: none
        }
      )
      
      ;; Update counter
      (var-set claim-counter claim-id)
      
      (ok claim-id)
    )
  )
)

;; Process claim (approve/reject)
(define-public (process-claim (claim-id uint) (approve bool))
  (let
    (
      (claim (unwrap! (map-get? incident-claims { claim-id: claim-id }) ERR_NOT_FOUND))
      (policy (unwrap! (map-get? policies { policy-id: (get policy-id claim) }) ERR_NOT_FOUND))
      (new-status (if approve CLAIM_APPROVED CLAIM_REJECTED))
    )
    (begin
      ;; Only contract owner can process claims
      (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
      
      ;; Verify claim is pending
      (asserts! (is-eq (get status claim) CLAIM_PENDING) ERR_NOT_AUTHORIZED)
      
      ;; Check coverage amount if approving
      (if approve
        (asserts! (<= (get damage-amount claim) (get coverage-amount policy)) ERR_INSUFFICIENT_COVERAGE)
        true
      )
      
      ;; Update claim status
      (map-set incident-claims
        { claim-id: claim-id }
        (merge claim {
          status: new-status,
          processed-at: (some stacks-block-height)
        })
      )
      
      ;; If approved, update total claims paid
      (if approve
        (var-set total-claims-paid (+ (var-get total-claims-paid) (get damage-amount claim)))
        true
      )
      
      (ok new-status)
    )
  )
)

;; Create recovery plan
(define-public (create-recovery-plan (claim-id uint) (recovery-steps (list 10 (string-ascii 128))) (estimated-timeline uint))
  (let
    (
      (claim (unwrap! (map-get? incident-claims { claim-id: claim-id }) ERR_NOT_FOUND))
    )
    (begin
      ;; Only contract owner or claim coordinator can create recovery plans
      (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
      
      ;; Verify claim is approved
      (asserts! (is-eq (get status claim) CLAIM_APPROVED) ERR_NOT_AUTHORIZED)
      
      ;; Store recovery plan
      (map-set recovery-plans
        { claim-id: claim-id }
        {
          recovery-steps: recovery-steps,
          coordinator: tx-sender,
          completion-status: u0, ;; 0 = not started, 100 = completed
          estimated-timeline: estimated-timeline
        }
      )
      
      (ok true)
    )
  )
)

;; Update recovery progress
(define-public (update-recovery-progress (claim-id uint) (completion-status uint))
  (let
    (
      (recovery-plan (unwrap! (map-get? recovery-plans { claim-id: claim-id }) ERR_NOT_FOUND))
    )
    (begin
      ;; Only recovery coordinator can update progress
      (asserts! (is-eq tx-sender (get coordinator recovery-plan)) ERR_NOT_AUTHORIZED)
      
      ;; Validate completion status (0-100)
      (asserts! (<= completion-status u100) ERR_INVALID_AMOUNT)
      
      ;; Update recovery plan
      (map-set recovery-plans
        { claim-id: claim-id }
        (merge recovery-plan {
          completion-status: completion-status
        })
      )
      
      (ok completion-status)
    )
  )
)

;; read only functions

;; Get policy details
(define-read-only (get-policy (policy-id uint))
  (map-get? policies { policy-id: policy-id })
)

;; Get security assessment
(define-read-only (get-security-assessment (assessment-id uint))
  (map-get? security-assessments { assessment-id: assessment-id })
)

;; Get incident claim
(define-read-only (get-incident-claim (claim-id uint))
  (map-get? incident-claims { claim-id: claim-id })
)

;; Get recovery plan
(define-read-only (get-recovery-plan (claim-id uint))
  (map-get? recovery-plans { claim-id: claim-id })
)

;; Get contract statistics
(define-read-only (get-contract-stats)
  {
    total-policies: (var-get policy-counter),
    total-assessments: (var-get assessment-counter),
    total-claims: (var-get claim-counter),
    total-premiums-collected: (var-get total-premiums-collected),
    total-claims-paid: (var-get total-claims-paid)
  }
)

;; Check if policy is active
(define-read-only (is-policy-active (policy-id uint))
  (match (map-get? policies { policy-id: policy-id })
    policy (and 
             (is-eq (get status policy) STATUS_ACTIVE)
             (< stacks-block-height (get expires-at policy))
           )
    false
  )
)

;; private functions

;; Calculate risk level based on assessment
(define-private (calculate-risk-level (risk-score uint) (vulnerabilities-count uint))
  (if (or (>= risk-score u80) (>= vulnerabilities-count u10))
    RISK_CRITICAL
    (if (or (>= risk-score u60) (>= vulnerabilities-count u5))
      RISK_HIGH
      (if (or (>= risk-score u40) (>= vulnerabilities-count u2))
        RISK_MEDIUM
        RISK_LOW
      )
    )
  )
)
