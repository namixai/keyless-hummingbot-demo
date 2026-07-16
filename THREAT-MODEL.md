# Threat model (public, demo-scoped)

An honest map of what this demo defends against and — just as important — what
it does **not**. We would rather you know the edges than discover them.

Adapted from the Usenami Signer public threat model; the sections below are
scoped to **this keyless Hummingbot demo** (the `POST /sign/binance-request`
path against Binance Futures **testnet**).

---

## Trust base (what you *do* have to trust)

The demo's security reduces to trusting these, and nothing about Usenami's honesty:

- **AWS Nitro Enclaves** — the hardware isolation of the enclave from its parent
  host, and the AWS **Nitro Attestation PKI** (the NSM signing chain rooted in
  the AWS Nitro root certificate).
- **AWS KMS** — that KMS enforces its own key policy, in particular the
  `kms:RecipientAttestation:ImageSha384` (PCR0) condition and the explicit deny
  of non-attested decrypt.
- **Standard cryptography** — SHA-2 / ECDSA (P-384) / Ed25519 / AES-GCM / HMAC as
  implemented by well-reviewed libraries.

If those hold, the properties below hold. What you can confirm **yourself,
trusting no Usenami code**, is narrower and precise: [VERIFY.md](VERIFY.md)
establishes the attestation's *authenticity* (signed by the AWS Nitro PKI), the
running image's *PCR0*, and *nonce-freshness*. Tying that PCR0 to what the image
actually **does** — its policy enforcement, KMS gating, tenant registry, and
authorization controls — additionally requires the reproducible rebuild from
source (production anchor, source access required); until you run that, those
behavioral properties rest on the source we publish, not on independent proof.

---

## What the demo protects

1. **The exchange key never touches your machine — or leaves the enclave.** The
   testnet API key behind your token is sealed (KMS envelope encryption) at
   provisioning and is only ever decryptable *inside* an enclave whose
   measurement (PCR0) matches the KMS key-policy allow-set. The bot receives a
   per-request signature and a transient `api_key` header value — never the secret.
2. **Not even the operator / AWS IAM / root can read the key off-enclave.** The
   KMS decrypt is attestation-gated; a non-attested principal is explicitly
   *denied*. Compromising the host, the operator's laptop, or an AWS admin role
   does **not** yield the plaintext key.
3. **Withdraw / transfer cannot be signed with your token.** Binance's HMAC
   covers request params only (never the URL path), so the enclave applies a
   **positive per-operation parameter allow-list** to the payload *before*
   signing. Trading and read params pass; withdraw / transfer / sub-account
   params exist in no allowed operation's schema — including a withdraw payload
   smuggled under an allowed operation name (this exact abuse is in the test
   suite). Denials return `403 action_not_allowed`.
4. **The token is revocable server-side, instantly.** Killing a token removes
   gateway access and its registry entry; the sealed key never needs to move.
5. **The tenant registry is authority-signed and replay-resistant.** Which token
   maps to which customer/venues is set only by an Ed25519-signed refresh bound
   to a fresh per-refresh nonce with a monotonic version; the signing key is
   held off-box.
6. **The running code is verifiable.** A live NSM-signed `/attestation` lets a
   third party confirm the exact enclave image (PCR0) — see [VERIFY.md](VERIFY.md).

---

## What the demo does NOT protect against

- **No per-asset order-size caps on this path.** The generic signing endpoint
  checks *which parameters* an operation may carry; it does **not** parse order
  semantics. An in-policy over-sized testnet order will be signed. (Signer's
  structured order path does enforce per-asset caps; a caps hook for this
  generic path is a prerequisite we hold ourselves to before any real-funds
  use.) **Do not describe this demo's token as "cap-bound" — it is not.**
- **A bad-but-allowed trade.** Within the allowed operations, the enclave signs
  what your bot submits. A buggy or compromised strategy can still lose (testnet)
  money by trading badly — the enclave constrains *what kind* of request can be
  signed, not whether it is wise.
- **Compromise of your bot machine's token.** The bearer token is the demo's
  credential: an attacker holding it can sign *allowed* operations (trade/read
  on testnet) until you revoke it. What they can never do — even with the token —
  is withdraw, transfer, or extract the exchange key. Treat the token like a
  password; rotation is cheap.
- **A vulnerability in the trust base itself.** A break in AWS Nitro isolation,
  the Nitro attestation PKI, KMS policy enforcement, or the underlying crypto is
  out of scope — the design *relies* on those. We reduce trust to AWS + math; we
  do not replace them.
- **Enclave side-channels.** The standard TEE caveat: micro-architectural /
  timing / power side-channels against the enclave are a research-grade risk
  inherent to confidential computing, not something we claim to eliminate.
- **Coercion or compromise of the human operator.** Attestation proves *what
  code runs*; it cannot prove *who authorized a grant*. The control-plane
  authority is currently held by a single operator; independent m-of-n
  credential redundancy is on the roadmap and is a prerequisite we hold
  ourselves to before large real-funds use.
- **Exchange-side risk.** If the exchange itself is compromised, mis-executes,
  or changes its API semantics, that is outside the signing boundary.
- **Availability.** The design is fail-**closed**: on any doubt the enclave
  refuses to sign. A fault shows up as *denied requests*, never as a leaked key.

---

## Maturity / honesty

- **No external audit yet.** Extensive internal review and self-run adversarial
  testing of the signing path — but **no independent security firm audit** at
  the time of writing; it is one of the milestones we gate real-funds use on.
  Until then the strongest assurance offered is *verifiability*
  ([VERIFY.md](VERIFY.md)).
- **Stage.** This demo and current integrations run on exchange **testnets**;
  real-funds use is gated behind the caps, redundancy, and audit milestones above.
- **Claims discipline.** Where a property is engineered but not yet independently
  demonstrated end-to-end, the docs say so explicitly rather than rounding up.

Found a gap not listed here? That is exactly the kind of thing we want to hear:
[business@usenami.io](mailto:business@usenami.io).
