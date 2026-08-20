# Legacy CUCM Research Notes

Notes on two long-standing, publicly-discussed weaknesses in the platform architecture of
early Cisco Unified Communications Manager (CUCM) releases (5.x-era, now long past end-of-life):

1. The `utils remote_account` TAC support-access mechanism.
2. The FlexLM-based licensing scheme used to enforce CCM_NODE / PHONE_UNIT entitlements.

Both topics have circulated in the CUCM admin/reseller/security community for over a decade
(see [References](#references)). This writeup consolidates and explains the underlying
architecture and *why* each mechanism is weak, at a conceptual level. It intentionally does
not include working exploit code, derivation algorithms, patched binaries, or automation —
see [Scope](#scope--methodology) below.

## Disclaimer

This is a technical architecture writeup, for educational purposes, about long-EOL
enterprise telephony infrastructure. Nothing here should be used against any system you
don't own or don't have explicit authorization to test.

## 1. The `utils remote_account` support-access mechanism

Cisco's UCOS-based platforms (CUCM, Unity Connection, UCCX, and others) ship a CLI command
for TAC-assisted remote support:

```
utils remote_account create <name> <days>
```

This creates a time-limited OS-level account and displays a **passphrase** — explicitly
*not* the account's login password. The intended flow is: the customer reads the passphrase
to a Cisco TAC engineer, who runs an internal Cisco tool to derive the real login password
from it, logs in, and helps troubleshoot.

### Why this is architecturally weak

The passphrase-to-password relationship is a **deterministic, offline-computable
transform** — not a server-side secret exchange, not rate-limited, and not tied to any
per-session server state. That's a meaningful design choice: it means the "secret" isn't
really the password, it's the *transform*. Once the transform is known to anyone outside
Cisco (and it has been — see the community references below, including a previously
circulating third-party "UCOS Decrypter" tool), the passphrase-gated barrier provides no
more protection than a static shared secret. Cisco itself acknowledged this over time by
changing the encoding algorithm in CUCM 14, which broke compatibility with the old
decrypter tooling — implicit confirmation that third parties had been computing these
passwords for years.

A second, compounding design choice: on these platforms, logging into the temporary support
account via SSH auto-invokes a `sudo`-wrapped script through the account's shell profile,
handing the session a root shell without further authentication. That's a common pattern in
embedded/appliance CLIs — pairing a "restricted" account with an automatic, unauthenticated
elevation path — and it converts any compromise of the restricted account (however it
happens) directly into full root.

This same general category of problem — a static or algorithmically-derivable path to a
root-equivalent account on Unified CM — resurfaced as recently as 2025's
[CVE-2025-20309](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-cucm-ssh-m4UBdpE7.html),
a maximum-severity advisory covering static root credentials left in certain Engineering
Special builds. The lesson is the same one the community had been writing about with the
5.x/6.x/7.x remote-support mechanism for over a decade: **a support-access backdoor is only
as strong as the secrecy of the mechanism that gates it**, and mechanisms don't stay secret
forever.

### Modeling the derivation class (illustrative, not the real transform)

At a purely structural level, any "passphrase → password" support-access scheme boils down
to a keyed transform:

```
password_candidate = Truncate( Encode( HMAC(K_static, passphrase) ), N )
```

where `K_static` is a fixed value baked into whatever tool performs the derivation. The
concrete choice of primitive (HMAC-SHA1, a block cipher, a bespoke bit-mixing routine —
the real CUCM tooling is not any of the specific things described here) barely matters to
the security argument. What matters is that `K_static` has to be physically present, in
recoverable form, inside a piece of software that ships to a party who is not supposed to
be able to compute passwords unassisted. That is a contradiction in terms: a key an
adversary can disassemble is not a secret, it's an inconvenience.

To make the mechanics concrete, here's a fully worked toy example with fabricated inputs
(none of these values are real CUCM constants):

```
K_static  = "S4mpleStaticKey!!"      (hypothetical, embedded in a hypothetical tool)
passphrase = "QW7X-PL2K"             (hypothetical, displayed by the CLI)

HMAC-SHA256(K_static, passphrase)
  = 38bfcdf3f7861ae08a51c18decf25b68d8e47b03c819b4db62107b71c961387b

password_candidate = first 10 chars of Base64(digest bytes), uppercased
  = "OL/N3/HXQZ"   (illustrative only)
```

Anyone holding `K_static` computes this in microseconds, offline, with no interaction with
Cisco and no rate limiting — because the entire "protocol" is a pure function of two known
inputs. The real-world version of this class of bug has a well-documented history: it's the
same reasoning behind why hardcoded API keys in mobile apps, hardcoded firmware update
signing keys, and hardcoded support-tool secrets all eventually leak — the key must be
distributed to be usable, and distribution and secrecy are in direct tension.

## 2. FlexLM licensing architecture

CUCM's licensing (CCM_NODE and PHONE_UNIT entitlements, among others) has historically been
built on Macrovision/Globetrotter FlexLM (later Flexera FlexNet), bundled as a set of JARs
on the box alongside Cisco-specific vendor classes. License authenticity is enforced via a
digital signature over the license certificate, checked by code that ships *on the box
itself* — inside the same FlexLM/Cisco JARs that hold (or reference) the private material
used for verification.

### Why this is architecturally weak

This is a classic "trust boundary co-located with the attacker" problem: the code that
decides whether a license is valid, and the box that an administrator (or anyone with root)
fully controls, are the same machine. Once an attacker has root — which, per Part 1, has
been achievable on these platforms for a long time — they also have a Java toolchain and
full access to the verification classes (`com.macrovision.flexlm.lictext.PriKey`
and related classes, per public writeups). Patching the verification logic to accept
arbitrary signatures is a natural consequence of enforcement living entirely client-side,
with no server-side or hardware-rooted anchor.

This is not a new observation for this product line — public writeups describing
essentially this approach go back to at least 2010 (see references), and Cisco's own
progressive hardening of the scheme across releases (weaker verification in the 5.x-8.x
era, ECC in later 9.x builds, RSA-2048 by 11.x) tracks the timeline of public "jailbreak"
tutorials fairly closely.

### The verification math, and why patching wins regardless of key size

License signature schemes are built on textbook digital-signature math. At a high level,
the vendor computes a hash `H` over the license's fields (feature name, count, expiry,
host ID, and so on), signs it with a private key, and embeds the signature in the license
file. The verifier — the code running on the customer's box — recomputes `H` over the same
fields and checks it against the signature using the corresponding public key. For RSA,
that check is literally: does `signature^e mod n` equal the expected hash?

Here's a complete toy RSA example with small, made-up numbers (nowhere close to real
key sizes — real FlexLM/Cisco keys are 2048-bit RSA or equivalent ECC — but the arithmetic
is exactly the same shape):

```
p = 17, q = 11                  →  n = p*q = 187
phi(n) = (p-1)(q-1) = 160
e = 7                            →  public exponent
d = 23                           →  private exponent (e*d ≡ 1 mod phi(n))

"license hash" m = 88            (stand-in for H(license fields); not a real hash)

Sign:    s = m^d mod n = 88^23 mod 187 = 11
Verify:  m' = s^e mod n = 11^7 mod 187 = 88   → m' == m, signature accepted
```

That's genuinely how RSA signature verification works, just at a scale small enough to
compute by hand. Scaling `n` up from 187 to a 617-digit (2048-bit) number, or switching to
elliptic-curve signatures, changes the *cost of forging a signature from scratch* by
many orders of magnitude — but it changes nothing about what happens after `Verify()`
returns. The verifier is still just a function call whose boolean result some other code
has to act on:

```
if Verify(pubkey, license_fields, signature):
    grant_entitlement()
else:
    deny_entitlement()
```

If an attacker has root on the box running that code, they don't need to break RSA-2048 at
all. They can patch the compiled class so `Verify()` always returns true, or replace the
embedded public key with one whose matching private key they hold and sign whatever they
want with it. Either way, the cryptographic strength of the *signature scheme* is entirely
beside the point — the vulnerability is that the trust boundary (the code deciding whether
to honor the signature) and the threat actor (an admin/attacker with root) are the same
machine. This is a generic lesson in software protection/DRM design, not specific to FlexLM:
client-side enforcement can only ever be as strong as the tamper-resistance of the client,
independent of key size.

## Lessons

- **Offline-computable secrets aren't secrets.** Any authentication step whose validity can
  be checked or derived without contacting the vendor's servers, and without rate limiting,
  should be assumed to be reversible given enough public attention.
- **Auto-elevation on login is a force multiplier for any account compromise.** A "limited"
  temporary support account is not limited if its shell profile hands out root for free.
- **Client-side license/entitlement enforcement is inherently soft** wherever the verifier
  and the value being protected live on the same box the customer (or attacker) controls
  root on. Hardware roots of trust, server-side validation, or periodic phone-home checks
  are the usual mitigations — and Cisco's own version history shows the licensing scheme
  moving in that direction over time.

## Scope & methodology

This writeup reflects architectural observations from lab-owned, end-of-life hardware,
cross-referenced against publicly available prior work (below). It does not reproduce any
Cisco or Flexera proprietary source or binary code, does not include the specific
passphrase-derivation transform, does not include patched class files or byte offsets, and
does not include any automation/tooling. It's a description of *why* these mechanisms are
weak, not a how-to.

## References

- [Cisco CUCM remote support account and access — Cisco Community](https://community.cisco.com/t5/unified-communications/cisco-cucm-remote-support-account-and-access/td-p/3299517)
- [Get Root Access to CUCM, CUC, UCCX just like TAC in less than a minute](https://www.uccollabing.com/get-root-access-to-cucm-cuc-uccx-easily-in-less-than-a-minute/)
- [Jail-breaking Cisco Unified Communication Manager — The Recurity Lablog](https://blog.recurity-labs.com/articles/jail-breaking_cisco_unified_communication_manager/index.html)
- [Cisco Licenses for VoIP and IPT: Unlock Cisco Unified Communications Manager Licenses (2010)](http://ciscolicenses.blogspot.com/2010/04/unlock-cisco-unified-communications.html)
- [CUCM 7.x Jailbreak License Tutorial: Adding Free Licenses](https://www.studocu.com/en-us/document/lurleen-b-wallace-community-college/network-communications/cucm-jailbreak-license/95889018)
- [Cisco Security Advisory: Cisco Unified Communications Manager Static SSH Credentials Vulnerability (CVE-2025-20309)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-cucm-ssh-m4UBdpE7.html)
- [BleepingComputer: Cisco removes Unified CM CallManager backdoor root account](https://www.bleepingcomputer.com/news/security/cisco-removes-unified-cm-callManager-backdoor-root-account/)

## License

Written content in this repository is licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
