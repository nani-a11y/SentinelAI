import base64
import re
import unicodedata

# Zero-width and invisible characters
ZERO_WIDTH_CHARS = {
    "\u200b",  # zero-width space
    "\u200c",  # zero-width non-joiner
    "\u200d",  # zero-width joiner
    "\u200e",  # left-to-right mark
    "\u200f",  # right-to-left mark
    "\ufeff",  # byte order mark / zero-width no-break space
    "\u00ad",  # soft hyphen
    "\u2060",  # word joiner
    "\u2061",  # function application
    "\u2062",  # invisible times
    "\u2063",  # invisible separator
    "\u2064",  # invisible plus
}

# Homoglyph replacements for common visual Cyrillic and Greek lookalikes
HOMOGLYPH_MAP = {
    # Cyrillic lowercase -> Latin visual lookalike
    "а": "a",  # U+0430
    "с": "c",  # U+0441
    "е": "e",  # U+0435
    "о": "o",  # U+043E
    "р": "p",  # U+0440 (visual 'p')
    "ѕ": "s",  # U+0455 (visual 's')
    "і": "i",  # U+0456 (visual 'i')
    "ј": "j",  # U+0458 (visual 'j')
    "у": "y",  # U+0443 (visual 'y')
    "х": "x",  # U+0445 (visual 'x')
    "һ": "h",  # U+04BB (visual 'h')
    "к": "k",  # U+043A
    # Cyrillic uppercase -> Latin visual lookalike
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I",
    "Ј": "J", "К": "K", "М": "M", "О": "O", "Р": "P", "Ѕ": "S",
    "Т": "T", "Х": "X", "Ү": "Y",
    # Greek lowercase -> Latin visual lookalike
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w",
    # Greek uppercase
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Р": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X",
}

# Base64 pattern candidate
BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

# Single-char spaced word pattern (e.g. "i g n o r e" or "s_y_s_t_e_m" or "p-r-o-m-p-t")
SPACED_LETTERS_PATTERN = re.compile(r"\b([a-zA-Z][\s\._\-\*]){3,}[a-zA-Z]\b")


def extract_base64_payloads(text: str) -> list[str]:
    """Attempt to decode suspicious base64 sequences within prompt text."""
    decoded_payloads: list[str] = []
    candidates = BASE64_PATTERN.findall(text)
    for cand in candidates:
        if len(cand) < 16:
            continue
        try:
            raw = base64.b64decode(cand)
            decoded = raw.decode("utf-8", errors="ignore").strip()
            # Verify decoded text looks like printable ASCII text
            if len(decoded) >= 8 and any(c.isalpha() for c in decoded) and decoded.isprintable():
                decoded_payloads.append(decoded)
        except Exception:
            continue
    return decoded_payloads


def collapse_spaced_words(text: str) -> str:
    """Collapse artificially spaced or delimited words (e.g., 'i g n o r e' -> 'ignore')."""
    def replacer(match: re.Match) -> str:
        matched = match.group(0)
        # Strip out spaces, dots, dashes, underscores, asterisks
        return re.sub(r"[\s\._\-\*]", "", matched)

    return SPACED_LETTERS_PATTERN.sub(replacer, text)


def normalize_text(text: str) -> tuple[str, list[str]]:
    """Normalize Unicode, strip invisible characters, map homoglyphs, and detect obfuscation.

    Returns:
        tuple[str, list[str]]: (normalized_inspection_text, detected_obfuscations)
    """
    detected_obfuscations: list[str] = []

    # 1. Check for zero-width / invisible characters
    cleaned_chars: list[str] = []
    has_zero_width = False
    for ch in text:
        if ch in ZERO_WIDTH_CHARS:
            has_zero_width = True
        else:
            cleaned_chars.append(ch)

    if has_zero_width:
        detected_obfuscations.append("zero_width_characters")

    clean_text = "".join(cleaned_chars)

    # 2. Unicode NFKD normalization
    decomposed = unicodedata.normalize("NFKD", clean_text)
    if decomposed != clean_text:
        detected_obfuscations.append("unicode_compatibility_normalization")

    # 3. Homoglyph substitution
    homoglyphs_found = False
    homoglyph_replaced: list[str] = []
    for ch in decomposed:
        if ch in HOMOGLYPH_MAP:
            homoglyph_replaced.append(HOMOGLYPH_MAP[ch])
            homoglyphs_found = True
        else:
            homoglyph_replaced.append(ch)

    if homoglyphs_found:
        detected_obfuscations.append("homoglyphs_detected")

    text_after_homoglyphs = "".join(homoglyph_replaced)

    # 4. Collapse artificially separated words
    collapsed_text = collapse_spaced_words(text_after_homoglyphs)
    if collapsed_text != text_after_homoglyphs:
        detected_obfuscations.append("spaced_character_obfuscation")

    # 5. Collapse excessive whitespace
    normalized_primary = re.sub(r"\s+", " ", collapsed_text).strip()

    # 6. Check for embedded Base64 payloads
    b64_payloads = extract_base64_payloads(text)
    inspection_text = normalized_primary
    if b64_payloads:
        detected_obfuscations.append("base64_encoded_payload")
        inspection_text = f"{normalized_primary} {' '.join(b64_payloads)}"

    return inspection_text, detected_obfuscations
