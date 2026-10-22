# eMudhra — compromised intermediate CA keys (October 2026)

Eight intermediate CA private keys operated under the **emSign** brand by **eMudhra**
(`eMudhra Technologies Limited`, C=IN): six TLS intermediates and two code-signing
intermediates. All eight were generated in a single April 2025 key ceremony by a faulty
script, and every private key turned out to be a *tiny integer* — from `4` to `237`.
Anybody holding the public certificate can recover the private key by brute force.

These keys are revoked and distrusted by the major browser and OS vendors. The files in
this repository exist as an archival / detection corpus: they are useful for scanning
your own estate for endpoints, bundles and appliances that still carry the affected
chains, and for regression-testing trust-store filtering.

---

## What happened

* **Weak entropy.** During an April 2025 key ceremony a faulty key-generation script
  produced ECDSA P-384 keys whose private scalar `d` was a single byte instead of a
  48-byte random value. The eight affected keys are `4, 56, 66, 115, 155, 156, 230, 237`.
  [1] (https://www.helpnetsecurity.com/2026/10/21/emudhra-certificates-private-keys-compromised/),
  [2] (https://blog.talosintelligence.com/compromised-intermediate-certificates/)

* **Public discovery.** Researchers recovered all eight private keys from the published
  certificates alone, within milliseconds, making every site or binary signed under those
  chains forgeable. [1] (https://www.linkedin.com/posts/pcissp_emudhra-story-is-being-reported-as-an-ai-activity-7518665657446580224-mzA2),
  [2] (https://www.theregister.com/security/2026/10/20/indian-certification-authority-emudhras-private-keys-compromised-one-of-them-was-the-number-4/5304312),
  [3] (https://blog.talosintelligence.com/compromised-intermediate-certificates/),
  [4] (https://www.instagram.com/reel/DewfsjGtoVN/)

* **No breach of core infrastructure.** eMudhra stated that its internal systems were not
  hacked and that no customer data was breached. Indian domestic eSign and DSC services
  regulated by India's Controller of Certifying Authorities remained unaffected.
  [1] (https://timesofindia.indiatimes.com/business/india-business/security-flaw-emudhra-shares-take-a-hit-fall-20/articleshow/135100962.cms),
  [2] (https://www.deccanherald.com/india/meity-forms-team-to-probe-emudhra-security-incident-says-impact-on-indian-websites-limited-4190574)

## Industry and browser response

* **Revocation and blocking.** eMudhra revoked the affected certificates. Google Chrome,
  Mozilla Firefox, Apple and Microsoft rapidly pushed updates to block the compromised
  keys. [1] (https://www.linkedin.com/posts/pcissp_emudhra-story-is-being-reported-as-an-ai-activity-7518665657446580224-mzA2),
  [2] (https://blog.talosintelligence.com/compromised-intermediate-certificates/),
  [3] (https://www.deccanherald.com/india/meity-forms-team-to-probe-emudhra-security-incident-says-impact-on-indian-websites-limited-4190574)

* **Action required.** Modern browsers and updated operating systems are protected, but
  servers, Linux CA bundles, embedded applications and pinned trust stores that do not
  auto-revoke need manual updates. [1] (https://www.helpnetsecurity.com/2026/10/21/emudhra-certificates-private-keys-compromised/),
  [2] (https://www.instagram.com/reel/DewfsjGtoVN/)

---

## The eight keys

All are `id-ecPublicKey`, curve `secp384r1` (P-384), signature algorithm `ecdsa-with-SHA384`,
`CA:TRUE, pathlen:0`, validity 2025-04-30 → 2040-04-28.

| Key | Business line | Subject O (entity) | d | Issuing root |
|---|---|---|---|---|
| `EM-DV-TLS-CA-G3B` | DV TLS | eMudhra BV (NL) | **156** | emSign Root TLS CA - G3 |
| `EM-DV-TLS-CA-G3C` | DV TLS | eMudhra Inc (US) | **230** | emSign Root TLS CA - G3 |
| `EM-EV-TLS-CA-G3B` | EV TLS | eMudhra BV (NL) | **115** | emSign Root TLS CA - G3 |
| `EM-EV-TLS-CA-G3C` | EV TLS | eMudhra Inc (US) | **56** | emSign Root TLS CA - G3 |
| `EM-OV-TLS-CA-G3B` | OV TLS | eMudhra BV (NL) | **155** | emSign Root TLS CA - G3 |
| `EM-OV-TLS-CA-G3C` | OV TLS | eMudhra Inc (US) | **4** | emSign Root TLS CA - G3 |
| `EM-OV-CS-CA-G3B` | OV Code Signing | eMudhra BV (NL) | **66** | emSign Root CS CA - G3 |
| `EM-OV-CS-CA-G3C` | OV Code Signing | eMudhra Inc (US) | **237** | emSign Root CS CA - G3 |

Suffixes: `-B` = **eMudhra BV** (Netherlands, `ocsp-b.emsign.com`), `-C` = **eMudhra Inc**
(United States, `ocsp-c.emsign.com`). The TLS intermediates also exist as a second,
cross-signed copy chaining to **AAA Certificate Services** (Sectigo / legacy Comodo CA),
so the impact spans two trust paths.

Certificate policies: `2.23.140.1.2.1` DV, `2.23.140.1.2.2` OV, `2.23.140.1.1` EV,
`2.23.140.1.4.1` code signing, plus eMudhra private policies
`1.3.6.1.4.1.50977.1.2.{100,110,120,200}` (PEN `1.3.6.1.4.1.50977`, CPS
`http://repository.emsign.com`).

## Layout

```
eMudhra/
├── README.md
├── SHA256SUMS.txt
├── private/     EM-<line>-<gen>.key.pem     PKCS#8, unencrypted
└── public/      EM-<line>-<gen>.pub.pem     SubjectPublicKeyInfo
```

`private/X.key.pem` and `public/X.pub.pem` are a matching pair, and both match the public
key of the real certificate `X` (see verification below). The certificates themselves are
in the capture set (`proof/*.crt.pem`), not duplicated here.

## How the keys were recovered

For each certificate, take the public point `Q` and exhaust `1 ≤ d < 2^17` in
`Q == d·G` on P-384. Because every `d` is below 256, the search hits on the first few
hundred point additions — all eight keys fall in well under a second in pure Python.
No lattice, no side channel: the keys were never random to begin with.

## Verification

```bash
# 1. private key -> public key, and compare against the certificate
openssl pkey -in private/EM-OV-TLS-CA-G3C.key.pem -pubout | openssl sha256
openssl x509 -in ../proof/EM-OV-TLS-CA-G3C.crt.pem -noout -pubkey | openssl sha256

# 2. make sure no file was tampered with
sha256sum -c SHA256SUMS.txt

# 3. (optional) confirm the scalar is tiny
openssl pkey -in private/EM-OV-TLS-CA-G3C.key.pem -text -noout | head -5
```

The `d = 4` key is the clearest illustration: in the DER encoding the 48-byte scalar is
`00…00 04`, so 24 leading zero bytes are visible in the PKCS#8 blob.

## Detecting affected chains in your estate

A chain is affected if **any** certificate in it carries one of the eight compromised
public keys. This matches on the public key, so it catches both the `emSign`-cross-signed
and the `AAA Certificate Services`-cross-signed copies of the same intermediate.

```bash
#!/bin/bash
# scan.sh <bundle-or-chain.pem>...   — list certificates using a compromised key
tmp=$(mktemp -d)
for p in public/*.pub.pem; do
  openssl pkey -pubin -in "$p" -outform DER | sha256sum | cut -d' ' -f1
done | sort > "$tmp/bad.txt"

for f in "$@"; do
  openssl crl2pkcs7 -nocrl -certfile "$f" 2>/dev/null \
    | openssl pkcs7 -print_certs -outform PEM 2>/dev/null \
    | awk -v d="$tmp/c" 'BEGIN{n=0} /BEGIN CERT/{n++} {print > (d n ".pem")}'
  for c in "$tmp"/c*.pem; do
    [ -s "$c" ] || continue
    h=$(openssl x509 -in "$c" -noout -pubkey 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
    grep -qx "$h" "$tmp/bad.txt" \
      && echo "AFFECTED  $f  ->  $(openssl x509 -in "$c" -noout -subject | sed 's/subject=//')"
  done
  rm -f "$tmp"/c*.pem
done
rm -rf "$tmp"
```

Example run against the capture set in this corpus (12 chains, 6 distinct keys hit) and
against a clean Mozilla-derived bundle (0 hits):

```
AFFECTED  chains/dv-g3b-aaa-emudhra.we-have-a-problem.com.pem -> C=NL, O=eMudhra BV, CN=EM DV TLS CA - G3B
AFFECTED  chains/dv-g3b-emudhra.we-have-a-problem.com.pem     -> C=NL, O=eMudhra BV, CN=EM DV TLS CA - G3B
...
```

The pragmatic check — does a trust store still *accept* a chain built on them:

```bash
openssl verify -show_chain -CAfile /path/to/bundle.pem \
  -untrusted chain-with-affected-intermediate.pem leaf.pem
```

Any `OK` means the store still trusts a compromised intermediate. Note that `openssl
verify` does not consult revocation unless explicitly asked to.

Serial numbers of the affected intermediates, for CT-log archaeology (which real customer
certificates were issued under them):

| Key | Serial |
|---|---|
| EM-DV-TLS-CA-G3B | `A4AEE678F23362B4C0E460B772F214` |
| EM-DV-TLS-CA-G3C | `588B2E3C2BB8CDA13E1A1209254321` |
| EM-EV-TLS-CA-G3B | `C7C41EFE92D825F05EAE841A4A82C1` |
| EM-EV-TLS-CA-G3C | `8009928A64107601AF05FA2F19F109` |
| EM-OV-TLS-CA-G3B | `6CADA367FB1C100088120EA202D568` |
| EM-OV-TLS-CA-G3C | `296926C227A3A1526392B19482A504` |
| EM-OV-CS-CA-G3B | `7818933F8F85B4619A2B35FBA83D0A` |
| EM-OV-CS-CA-G3C | `544B7F922C31AE220A4A922916F6E6` |

## Remediation checklist

1. Remove/distrust the eight intermediates — do not wait for the 2040 expiry.
2. Patch trust stores that do not auto-revoke: Linux CA bundles, Java `cacerts`,
   container images, network appliances, firmware, pinned mobile apps.
3. Re-issue any certificate or code-signing identity that was anchored on these
   intermediates.
4. For code signing: treat binaries signed under `emSign Root CS CA - G3` sub-CAs as
   untrusted; re-sign and re-release.
5. Scan CT logs by the serial numbers above to enumerate real affected domains.

## Provenance

Key material derived from the certificate chains captured on 20 October 2026 from the
`*.we-have-a-problem.com` test hosts (`dv|ov|ev-g3b|g3c[-aaa]-emudhra.we-have-a-problem.com`),
plus the `proof/` signature set that demonstrates possession of each key. Private keys were
recomputed from the public keys; nothing here was obtained by breaching eMudhra systems.

The `.sig` proofs in the source set are ECDSA-SHA384 over the ASCII message
`We have a problem here - Wayne`, and were produced with a healthy CSPRNG (full-size,
non-repeated nonces) — i.e. by the researchers, not by the faulty CA key-generation
pipeline.

## Disclaimer

Published for defensive purposes: incident documentation, detection engineering, and
trust-store regression testing. These keys belong to certificates that are revoked and
distrusted; using them to issue certificates or sign code is forgery and, in most
jurisdictions, a criminal offence. Do not import them into any production trust anchor.

## References

1. https://blog.cloudflare.com/emudhra-certificate-compromise/
2. https://timesofindia.indiatimes.com/business/india-business/security-flaw-emudhra-shares-take-a-hit-fall-20/articleshow/135100962.cms
3. https://www.deccanherald.com/india/meity-forms-team-to-probe-emudhra-security-incident-says-impact-on-indian-websites-limited-4190574
4. https://blog.talosintelligence.com/compromised-intermediate-certificates/
5. https://www.instagram.com/reel/DewfsjGtoVN/
6. https://www.theregister.com/security/2026/10/20/indian-certification-authority-emudhras-private-keys-compromised-one-of-them-was-the-number-4/5304312
7. https://www.helpnetsecurity.com/2026/10/21/emudhra-certificates-private-keys-compromised/
8. https://www.linkedin.com/posts/pcissp_emudhra-story-is-being-reported-as-an-ai-activity-7518665657446580224-mzA2
