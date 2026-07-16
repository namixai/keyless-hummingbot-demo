# Verify the Signer yourself

The demo's security claim — *your exchange key lives only inside an attested
AWS Nitro Enclave* — is checkable with your own tools. This walkthrough trusts
**AWS** (Nitro hardware, the Nitro Attestation PKI, KMS honoring its own key
policy) and **standard cryptography**. It does not require trusting Usenami.

You verify that the live service runs the **exact enclave image** whose
fingerprint (**PCR0**) is published — via a live, NSM-signed attestation
document, not via anything Usenami asserts in-band.

> Adapted from the Signer verification docs. Two further layers — rebuilding
> the image from source to derive the same PCR0 yourself (reproducible build),
> and the on-chain PCR0 registry — are production anchors: the source walkthrough
> is available with source access ([business@usenami.io](mailto:business@usenami.io)),
> and this **testnet demo is NOT registered on-chain** (its `/attestation`
> honestly returns `registered_onchain: false`).

## What `/attestation` gives you

`GET /attestation?nonce=<hex>` returns a **live COSE attestation document signed
by the AWS Nitro Secure Module**, bound to your nonce (anti-replay), served
`Cache-Control: no-store`. The gateway is untrusted for this proof — you check
the signature yourself against the AWS Nitro root certificate and read PCR0 out
of the *signed* document.

> Do **not** trust the plaintext `pcr0_sha384` JSON field on its own — it is a
> convenience mirror. The signed COSE document is the source of truth.

The checks, in order:

1. **Fetch** with a fresh random `nonce`; confirm `Cache-Control: no-store`.
2. **Pin** the AWS Nitro Enclaves root certificate out-of-band (compare its
   SHA-256 to a value obtained independently — AWS docs / a second channel).
3. **Validate the certificate path** (RFC 5280): leaf → `cabundle` → the pinned
   AWS Nitro root, as-of the attestation timestamp. Use a vetted validator —
   don't hand-roll chain building.
4. **Verify the COSE `ES384` signature** with the leaf public key over the
   `Signature1` structure.
5. **Read PCR0** from the verified `pcrs[0]`; compare to the published value below.
6. **Check the nonce** inside the verified document equals the one you sent.

## Copy-paste verifier (Python, trusts no Usenami code)

```bash
python3 -m venv v && . v/bin/activate && pip install cbor2 cryptography certvalidator requests

# AWS Nitro Enclaves root — download, then PIN its hash. Value at time of writing:
#   6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0
# Confirm that hash OUT-OF-BAND (AWS documentation / a second channel).
curl -sO https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
unzip -o AWS_NitroEnclaves_Root-G1.zip     # → root.pem
sha256sum root.pem
```

```python
#!/usr/bin/env python3
# Reference verifier — trusts no Usenami code. Security checks RAISE explicitly
# (never `assert`; `python -O` strips asserts). The cert path is validated by
# certvalidator, anchored to the PINNED root and as-of the attestation timestamp
# (the leaf certs are short-lived); COSE ES384 / PCR0 / nonce are checked explicitly.
import base64, hashlib, os, datetime, requests, cbor2
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError, PathBuildingError

def check(cond, msg):
    if not cond:
        raise SystemExit(f"ATTESTATION VERIFY FAILED: {msg}")

BASE          = os.environ.get("SIGNER_URL", "https://signer-demo.usenami.io:8443")
# The PCR0 published for the demo enclave (see "Where the expected PCR0 comes
# from" below).
EXPECTED_PCR0 = os.environ.get(
    "EXPECTED_PCR0",
    "ff53e1fe23498737e647a3baf0706133c4b157af024a519bf9d983a1f538d356e01f05792e15837728a7829c2908f6c6",
).lower()
ROOT_PEM      = open("root.pem", "rb").read()
# The AWS Nitro root hash you PINNED out-of-band (default = the value shown above).
ROOT_SHA256   = os.environ.get(
    "NITRO_ROOT_SHA256",
    "6eb9688305e4bbca67f44b59c29a0661ae930f09b5945b5d1d9ae01125c8d6c0",
).lower()

# 0) Pin the AWS Nitro root before trusting anything.
check(hashlib.sha256(ROOT_PEM).hexdigest() == ROOT_SHA256, "Nitro root cert hash mismatch")

# 1) Fetch a FRESH doc bound to our nonce; confirm it is not cached.
nonce = os.urandom(16).hex()
r = requests.get(f"{BASE}/attestation", params={"nonce": nonce}, timeout=15)
r.raise_for_status()
check(r.headers.get("cache-control") == "no-store", "attestation must be no-store")

# 2) Parse COSE_Sign1 (may be CBOR tag 18) = [protected, unprotected, payload, sig].
cose = cbor2.loads(base64.b64decode(r.json()["attestation_doc_b64"]))
if isinstance(cose, cbor2.CBORTag):        # tag 18 = COSE_Sign1
    cose = cose.value
protected_bstr, _unprotected, payload_bstr, sig = cose
doc = cbor2.loads(payload_bstr)            # the AttestationDocument

# 3) FULL RFC 5280 path validation, anchored to the PINNED root, as-of the
#    attestation time. certvalidator builds + validates the path itself, so
#    cabundle ordering, DN chaining, CA/basic-constraints, path length, and
#    critical extensions are all handled — nothing hand-rolled.
moment = datetime.datetime.fromtimestamp(doc["timestamp"] / 1000, datetime.timezone.utc)
vc = ValidationContext(trust_roots=[ROOT_PEM], allow_fetching=False, moment=moment)
try:
    CertificateValidator(doc["certificate"], intermediate_certs=list(doc["cabundle"]),
                         validation_context=vc).validate_usage(set())
except (PathValidationError, PathBuildingError) as e:
    raise SystemExit(f"ATTESTATION VERIFY FAILED: cert path: {e}")

# 4) Enforce the COSE metadata BEFORE trusting the signature: the protected
#    header must advertise alg = ES384 (-35), the signature must be a 96-byte
#    raw r||s, and the leaf key must be on P-384 — otherwise a document could
#    claim a weaker/mismatched algorithm than we verify with.
phdr = cbor2.loads(protected_bstr) if protected_bstr else {}
check(isinstance(phdr, dict), "COSE protected header is not a map")
check(phdr.get(1) == -35, f"COSE alg is not ES384 (-35): {phdr.get(1)}")
check(len(sig) == 96, f"COSE signature is not 96-byte P-384 r||s: {len(sig)}")
leaf = x509.load_der_x509_certificate(doc["certificate"])
pub = leaf.public_key()
check(isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP384R1),
      "leaf certificate key is not P-384")

# Verify the COSE ES384 signature with the LEAF public key.
# Sig_structure = ["Signature1", protected, external_aad(=b""), payload], CBOR-encoded.
sig_structure = cbor2.dumps(["Signature1", protected_bstr, b"", payload_bstr])
r_int = int.from_bytes(sig[:48], "big"); s_int = int.from_bytes(sig[48:], "big")  # P-384 raw r||s
pub.verify(utils.encode_dss_signature(r_int, s_int), sig_structure,
           ec.ECDSA(hashes.SHA384()))   # raises on mismatch

# 5) Check PCR0 and the nonce INSIDE the verified document.
pcr0 = doc["pcrs"][0].hex()
check(pcr0 == EXPECTED_PCR0, f"PCR0 mismatch: doc={pcr0} expected={EXPECTED_PCR0}")
check(doc["nonce"] == bytes.fromhex(nonce), "nonce not bound — possible replay")

print(f"OK — path valid to pinned root, COSE signature valid, PCR0={pcr0} matches, nonce fresh.")
```

Run it — the published pins are baked in as defaults, so it works as-is against
the public demo:

```bash
python3 verify.py
```

Any tampering fails loudly: a forged document breaks the COSE signature; a
document from a different image fails the PCR0 check; a stale/cached document
fails the nonce check; a non-AWS chain fails the pinned-root path validation.

## Where the expected PCR0 comes from

The value baked in above — `ff53e1fe…f6c6` — is the PCR0 the **public demo**
enclave currently attests, published here as a reference (only as trustworthy
as this repo). The zero-trust source is your **own reproducible rebuild** of the
enclave image from source, which derives PCR0 with no input from Usenami — ask
via [business@usenami.io](mailto:business@usenami.io) for the source walkthrough.
A PCR0 changes whenever any build pin changes; that is a re-attestation event,
never a silent swap.
