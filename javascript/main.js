//  CHARACTER POOLS
const POOLS = {
    upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    lower: "abcdefghijklmnopqrstuvwxyz",
    digits: "0123456789",
    symbols: "!@#$%^&*()-_=+[]{}|;:,.<>?/~",
};

const AMBIGUOUS = new Set("0Ol1I|B8S5");

//  SECURE RANDOM INTEGER - no modulo bias
//  Uses rejection sampling over a power-of-2
//  aligned range so every index is equally likely
function secureRandInt(max) {
    if (max <= 0) throw new RangeError("max must be > 0");
    // smallest power-of-2 bitmask ≥ max
    const buf = new Uint32Array(1);
    let mask = 1;
    while (mask < max) mask = (mask << 1) | 1;
    let val;
    do {
        crypto.getRandomValues(buf);
        val = buf[0] & mask;
    } while (val >= max); // rejection: guarantees uniform distribution
    return val;
}

//  FISHER-YATES SHUFFLE using CSPRNG
function secureShuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
        const j = secureRandInt(i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
}

//  MAIN GENERATION ALGORITHM
function generatePassword() {
    const length = parseInt(document.getElementById("lengthSlider").value);
    const useUpper = document.getElementById("chkUpper").checked;
    const useLower = document.getElementById("chkLower").checked;
    const useDigits = document.getElementById("chkDigits").checked;
    const useSymbols = document.getElementById("chkSymbols").checked;
    const noAmbig = document.getElementById("chkNoAmbig").checked;
    const guarantee = document.getElementById("chkGuarantee").checked;

    // Build the active pools
    const activePools = [];
    if (useUpper) activePools.push({ key: "upper", chars: POOLS.upper });
    if (useLower) activePools.push({ key: "lower", chars: POOLS.lower });
    if (useDigits) activePools.push({ key: "digits", chars: POOLS.digits });
    if (useSymbols) activePools.push({ key: "symbols", chars: POOLS.symbols });

    if (activePools.length === 0) {
        setStatus("Select at least one character type!");
        return;
    }

    // Apply ambiguity filter
    const filteredPools = activePools
        .map((p) => ({
            ...p,
            chars: noAmbig ? [...p.chars].filter((c) => !AMBIGUOUS.has(c)).join("") : p.chars,
        }))
        .filter((p) => p.chars.length > 0);

    if (filteredPools.length === 0) {
        setStatus("No characters remain after ambiguity filter!");
        return;
    }

    // Combined alphabet for bulk sampling
    const alphabet = filteredPools.map((p) => p.chars).join("");

    const chars = [];

    // Guarantee at least one character from each active pool (prevents weak outputs)
    if (guarantee) {
        for (const pool of filteredPools) {
            if (pool.chars.length > 0) {
                chars.push(pool.chars[secureRandInt(pool.chars.length)]);
            }
        }
    }

    // Fill remaining positions from the full combined alphabet
    const remaining = length - chars.length;
    for (let i = 0; i < remaining; i++) {
        chars.push(alphabet[secureRandInt(alphabet.length)]);
    }

    // Cryptographically secure shuffle to eliminate positional patterns
    secureShuffle(chars);

    const password = chars.join("");

    // Display
    document.getElementById("passwordDisplay").textContent = password;
    updateStrength(password, alphabet.length);
    addHistory(password);
    setStatus(`Generated ${length}-char password using ${filteredPools.length} character pool(s)`);
}

//  SHANNON ENTROPY ESTIMATE
//  H = L x log2(N) where L = length, N = pool size
function calcEntropy(password, alphabetSize) {
    return Math.round(password.length * Math.log2(alphabetSize));
}

function updateStrength(password, alphabetSize) {
    const entropy = calcEntropy(password, alphabetSize);
    const bar = document.getElementById("strengthBar");
    const text = document.getElementById("strengthText");
    const entText = document.getElementById("entropyText");

    entText.textContent = `Entropy: ~${entropy} bits`;

    // Thresholds based on NIST guidance and modern GPU cracking benchmarks
    let label, color, pct;
    if (entropy < 40) {
        label = "Weak";
        color = "#cc0000";
        pct = 15;
    } else if (entropy < 60) {
        label = "Fair";
        color = "#cc6600";
        pct = 35;
    } else if (entropy < 80) {
        label = "Good";
        color = "#ccaa00";
        pct = 55;
    } else if (entropy < 100) {
        label = "Strong";
        color = "#008800";
        pct = 75;
    } else if (entropy < 128) {
        label = "Very Strong";
        color = "#006600";
        pct = 88;
    } else {
        label = "Uncrackable";
        color = "#000080";
        pct = 100;
    }

    bar.style.width = pct + "%";
    bar.style.background = color;
    text.textContent = label;
}

//  COPY TO CLIPBOARD
function copyPassword() {
    const pw = document.getElementById("passwordDisplay").textContent;
    if (!pw || pw.startsWith("Click")) return;
    navigator.clipboard.writeText(pw).then(() => {
        const notif = document.getElementById("copyNotif");
        notif.style.display = "block";
        setTimeout(() => (notif.style.display = "none"), 1800);
        setStatus("Password copied to clipboard");
    });
}

//  SESSION HISTORY (in-memory only, never stored)
const history = [];

function addHistory(pw) {
    history.unshift(pw);
    if (history.length > 10) history.pop();
    renderHistory();
}

function renderHistory() {
    const box = document.getElementById("historyBox");
    box.innerHTML = history
        .map(
            (p) =>
                `<div class="history-item" onclick="navigator.clipboard.writeText('${p.replace(/'/g, "\\'")}');setStatus('Copied from history')">${p}</div>`
        )
        .join("");
}

function clearHistory() {
    history.length = 0;
    renderHistory();
    setStatus("History cleared");
}

function setStatus(msg) {
    document.getElementById("statusPane").textContent = msg;
}

// Generate one on load
generatePassword();