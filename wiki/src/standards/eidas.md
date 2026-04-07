# eIDAS 2.0

## What Is eIDAS

The **European Digital Identity Framework** (eIDAS 2.0) mandates that every EU citizen will have access to a digital identity wallet by 2026. The wallet stores government-issued credentials — national ID, driving license, diplomas, health records — and allows selective disclosure to verifiers.

The regulation (EU 2024/1183, amending EU 910/2014) introduces:

- **EUDI Wallet**: a mobile app issued by member states, holding personal identification data (PID) and attestations
- **PID (Person Identification Data)**: the core credential — name, birthdate, nationality, document number
- **EAA (Electronic Attestation of Attributes)**: additional credentials (diplomas, health data, vehicle registration)
- **QEAA (Qualified EAA)**: attestations issued or signed by qualified trust service providers, carrying legal weight equivalent to handwritten signatures

## Where ZK Proofs Fit

The Architecture Reference Framework (ARF) acknowledges the need for **selective disclosure** — a verifier checking age shouldn't learn the holder's name. Current approaches (SD-JWT VC, mdoc selective disclosure) reveal individual claims. ZK proofs go further: they prove predicates ("age >= 18") without revealing the claim value ("born 1998-05-14") at all.

zk-eidas implements this for mdoc credentials:

1. Issuer issues a standard ISO 18013-5 mdoc — no changes to issuance
2. Holder generates a ZK proof that a predicate holds on a claim
3. Verifier checks the proof — learns only the predicate result
4. Optionally: a QTSP co-signs the proof as a QEAA for legal recognition

## QEAA in zk-eidas

The TSP attestation feature wraps ZK proofs as QEAAs:

- The proof envelope becomes the `credentialSubject` of a W3C Verifiable Credential
- A qualified trust service provider signs with ECDSA P-256 (DataIntegrityProof)
- The resulting QEAA has legal standing under eIDAS Article 45

In production, the TSP would be a qualified trust service registered in a Trusted Service List (TSL). The demo uses an ephemeral keypair.

## Credential Formats

eIDAS 2.0 supports two credential formats:

| Format | Standard | Used By | zk-eidas Support |
|--------|----------|---------|-----------------|
| **SD-JWT VC** | RFC 9901 | EUDI Wallet reference | v1 only (removed in v2) |
| **mdoc/mDL** | ISO 18013-5 | Google Wallet, EUDI Wallet | Full support |

zk-eidas v2 focuses on mdoc — the format used by Google Wallet's mDL implementation, which Longfellow was designed for.
