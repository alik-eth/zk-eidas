# Predicate Reference

Predicates are conditions proven about credential claims without revealing the claim values.

## Predicate Types

| Predicate | VerifyType | Description | Example |
|-----------|-----------|-------------|---------|
| `gte` | `Geq (2)` | Greater than or equal | `birth_date <= 2008-04-07` (age >= 18) |
| `lte` | `Leq (1)` | Less than or equal | `age <= 65` |
| `eq` | `Eq (0)` | Equality | `nationality == "DE"` |
| `neq` | `Neq (3)` | Not equal | `status != "revoked"` |
| `range` | Two attrs | Range check (Leq + Geq) | `18 <= age <= 25` |
| `set_member` | Multiple Eq | Set membership (up to 16) | `nationality in {"DE", "FR", "NL"}` |
| `nullifier` | (built-in) | Scoped replay prevention | One proof per contract per credential |
| `holder_binding` | (built-in) | Cross-credential linking | Same holder, different credentials |
| `identity_escrow` | (out-of-circuit) | Encrypted identity recovery | Decrypt only by escrow authority |

## How Predicates Work

Longfellow evaluates predicates inside a **single extended hash circuit**. The `assert_attribute()` function compares CBOR byte values lexicographically:

- **Geq**: credential bytes >= threshold bytes
- **Leq**: credential bytes <= threshold bytes
- **Eq**: both Leq and Geq hold
- **Neq**: NOT Eq

Date strings (`"1998-09-04"`) compare correctly because ISO 8601 dates sort naturally. No epoch conversion inside the circuit.

## Compound Predicates

Multiple predicates combine with AND/OR logic. In Longfellow, compound predicates are multiple `AttributeRequest` entries in a single prove call — one proof covers everything.

## Predicate Templates

| Template | Claim | Description |
|----------|-------|-------------|
| `age_over_18` | birth_date | Age >= 18 at current date |
| `age_over_21` | birth_date | Age >= 21 at current date |
| `age_over_65` | birth_date | Age >= 65 at current date |
| `eu_nationality` | nationality | EU citizenship (27 countries) |
| `schengen_residency` | resident_country | Schengen area residency |

## Circuit Constraints

The circuit supports 1-4 attributes per proof. Range predicates consume 2 slots (Leq + Geq). Set membership consumes one slot per element, practical limit 16.
