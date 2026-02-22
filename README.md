# PassGen 98

> A strong, cryptographically secure password generator with a Windows 98 UI aesthetic. Single-file. No dependencies. No server. No tracking.

![PassGen 98 Screenshot](https://github.com/D3F4ULT-D3V/PassGen-98/blob/main/.github/images/PassGen.png)

---

## What It Is?

PassGen 98 is a self-contained HTML/CSS/JS password generator that runs entirely in your browser. It uses your browser's native **Cryptographically Secure Pseudorandom Number Generator (CSPRNG)** to generate passwords that are resistant to brute-force, dictionary, and credential-stuffing attacks.

There is no backend, no network request, no localStorage, and no cookies. Every password exists only in memory for the duration of your session.

---

## Why Strong Password Generation Is Hard to Get Right?

Most password generators have subtle but serious flaws in their randomness. The two most common are:

### 1. Using `Math.random()`
JavaScript's `Math.random()` is a **Pseudorandom Number Generator (PRNG)**, not a CSPRNG. Its output is deterministic, if an attacker knows or can guess the internal seed, they can reproduce every "random" number the generator ever produced.

PassGen uses `crypto.getRandomValues()` instead, which pulls entropy from the operating system itself (hardware events, interrupt timing, etc.) and is suitable for cryptographic use.

### 2. Modulo Bias
Even with a good random source, a naive `randomInt % poolSize` introduces **modulo bias**, lower-indexed characters in the pool appear slightly more often than they should. In a pool of 94 characters drawn from a 32-bit integer, the bias is small but measurable, and it statistically weakens the password.

PassGen 98 eliminates this with **rejection sampling**:

```js
function secureRandInt(max) {
  const buf = new Uint32Array(1);
  let mask = 1;
  while (mask < max) mask = (mask << 1) | 1; // smallest bitmask >= max
  let val;
  do {
    crypto.getRandomValues(buf);
    val = buf[0] & mask;
  } while (val >= max); // reject out-of-range values and resample
  return val;
}
```

Every integer in `[0, max)` is equally likely. No character in the pool has a statistical edge over any other.

---

## Generation Algorithm

Password generation happens in four distinct steps:

### Step 1: Build the Character Pool
The user selects which character sets to include:
- Uppercase letters: `A–Z` (26 chars)
- Lowercase letters: `a–z` (26 chars)
- Digits: `0–9` (10 chars)
- Symbols: `!@#$%^&*()-_=+[]{}|;:,.<>?/~` (29 chars)

An optional **ambiguity filter** removes characters that are visually similar and easy to misread: `0`, `O`, `o`, `l`, `1`, `I`, `|`, `B`, `8`, `S`, `5`. This is useful when a password will be read and typed manually rather than copy-pasted.

### Step 2: Guarantee Coverage (Optional)
When the "Guarantee each char type" option is enabled, the generator seeds the password with at least one character drawn from each active pool before filling the rest. This ensures you never get a 20-character password that happens to contain no symbols due to random chance.

```js
for (const pool of filteredPools) {
  chars.push(pool.chars[secureRandInt(pool.chars.length)]);
}
```

### Step 3: Fill Remaining Positions
The remaining character slots are filled by sampling uniformly from the **combined alphabet** (all active pools merged). Each character is independently and uniformly drawn using `secureRandInt`.

```js
const remaining = length - chars.length;
for (let i = 0; i < remaining; i++) {
  chars.push(alphabet[secureRandInt(alphabet.length)]);
}
```

### Step 4: Cryptographic Shuffle (Fisher-Yates)
Because Step 2 places guaranteed characters at known positions, the array is shuffled using a **CSPRNG-powered Fisher-Yates algorithm** before the password is assembled. This eliminates all positional patterns, an attacker cannot infer which characters are "guaranteed" or where they appear.

```js
function secureShuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = secureRandInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}
```

Fisher-Yates with a uniform random source produces every possible permutation with equal probability, there are no preferred orderings.

---

## Entropy & Strength Estimation

Entropy is measured in **bits** using the Shannon formula:

```
H = L x log₂(N)
```

Where:
- `L` = password length (number of characters)
- `N` = size of the combined alphabet (number of distinct characters available)
- `H` = entropy in bits

This measures the theoretical unpredictability of the password. A higher bit count means more possible combinations an attacker must search through.

### Strength Thresholds

| Entropy      | Rating        | Context |
|--------------|---------------|---------|
| < 40 bits    | Weak        | Crackable in seconds with modern GPUs |
| 40–59 bits   | Fair        | Crackable in hours/days offline |
| 60–79 bits   | Good        | Resistant to most attacks |
| 80–99 bits   | Strong      | Would take years on dedicated hardware |
| 100–127 bits | Very Strong | Beyond practical offline attack |
| 128+ bits    | Uncrackable | Computationally infeasible with known technology |

128 bits of entropy is the gold standard because it exceeds the security level of AES-128 encryption. For reference, a 20-character password drawn from all four character pools (95 chars) yields approximately **131 bits** of entropy.

### Example Entropy Values

| Length | Pool        | Approx. Entropy |
|--------|-------------|-----------------|
| 12     | lowercase only (26) | 56 bits |
| 12     | all types (91)      | 79 bits |
| 20     | all types (91)      | 131 bits |
| 32     | all types (91)      | 210 bits |

---

## What It Does Not Do

PassGen 98 is a **generator**, not a **manager**. It does not:

- Store passwords anywhere (no localStorage, no cookies, no server)
- Autofill login forms
- Sync across devices
- Remember which password belongs to which account

For storing generated passwords, pair it with a dedicated password manager like [KeePass](https://keepass.info/), [Bitwarden](https://bitwarden.com/), or [1Password](https://1password.com/).

---

## Usage

No installation, no build step, no dependencies.

```bash
# Just open the file
open index.html
```

## Options Reference

| Option | Description |
|--------|-------------|
| **Password Length** | Slider from 12 to 64 characters. Minimum of 12 is enforced as anything shorter falls below 60 bits even with a full character pool. |
| **Uppercase (A–Z)** | Includes the 26 uppercase Latin letters |
| **Lowercase (a–z)** | Includes the 26 lowercase Latin letters |
| **Digits (0–9)** | Includes the 10 decimal digits |
| **Symbols** | Includes 29 common symbols: `!@#$%^&*()-_=+[]{}|;:,.<>?/~` |
| **Exclude ambiguous** | Removes `0`, `O`, `l`, `1`, `I`, `|`, `B`, `8`, `S`, `5` — useful for passwords typed manually |
| **Guarantee each char type** | Ensures at least one character from every selected pool appears in the output |

---

## Design Philosophy

The security properties are grounded in published guidance:

- **OWASP Password Storage Cheat Sheet** for entropy thresholds and algorithm selection rationale
- **NIST SP 800-63B** for understanding what "sufficient" password entropy means in practice  
- **W3C Web Cryptography API spec** for correct usage of `crypto.getRandomValues()`

The UI aesthetic is purely for fun. The cryptography is not.
