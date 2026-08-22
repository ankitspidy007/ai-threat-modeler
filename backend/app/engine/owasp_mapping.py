"""
CWE to OWASP Top 10 (2021) mapping for findings that carry a CWE but no
explicit OWASP category.

Source of truth is the CWE list OWASP publishes for each 2021 category. Two
deliberate deviations are marked inline: OWASP files the "missing encryption"
CWEs (311-317) and error-message disclosure (209) under A04, while both the
A02 and A05 category descriptions explicitly cover those conditions, and every
reviewer expects to see them there. CWEs that OWASP does not list at all are
mapped to the category whose description covers them, and are marked below.
"""

from typing import Dict, Iterable, List, Optional


A01 = 'A01:2021 Broken Access Control'
A02 = 'A02:2021 Cryptographic Failures'
A03 = 'A03:2021 Injection'
A04 = 'A04:2021 Insecure Design'
A05 = 'A05:2021 Security Misconfiguration'
A06 = 'A06:2021 Vulnerable and Outdated Components'
A07 = 'A07:2021 Identification and Authentication Failures'
A08 = 'A08:2021 Software and Data Integrity Failures'
A09 = 'A09:2021 Security Logging and Monitoring Failures'
A10 = 'A10:2021 Server-Side Request Forgery'


OWASP_2021_BY_CWE: Dict[int, str] = {
    # A01 Broken Access Control
    22: A01, 23: A01, 35: A01, 59: A01, 200: A01, 201: A01, 219: A01, 275: A01,
    276: A01, 284: A01, 285: A01, 352: A01, 359: A01, 377: A01, 402: A01,
    425: A01, 441: A01, 497: A01, 538: A01, 540: A01, 548: A01, 552: A01,
    566: A01, 601: A01, 639: A01, 651: A01, 668: A01, 706: A01, 732: A01,
    862: A01, 863: A01, 913: A01, 922: A01, 1275: A01,
    250: A01,  # not listed by OWASP; unnecessary privilege is access control
    # A02 Cryptographic Failures
    261: A02, 296: A02, 310: A02, 319: A02, 321: A02, 322: A02, 323: A02,
    324: A02, 325: A02, 326: A02, 327: A02, 328: A02, 329: A02, 330: A02,
    331: A02, 335: A02, 336: A02, 337: A02, 338: A02, 340: A02, 347: A02,
    523: A02, 720: A02, 757: A02, 759: A02, 760: A02, 780: A02, 818: A02,
    916: A02,
    320: A02,  # not listed by OWASP; key management is a cryptographic failure
    311: A02, 312: A02, 313: A02, 314: A02, 315: A02, 316: A02, 317: A02,  # deviation
    # A03 Injection
    20: A03, 74: A03, 75: A03, 77: A03, 78: A03, 79: A03, 80: A03, 83: A03,
    87: A03, 88: A03, 89: A03, 90: A03, 91: A03, 93: A03, 94: A03, 95: A03,
    96: A03, 97: A03, 98: A03, 99: A03, 100: A03, 113: A03, 116: A03,
    138: A03, 184: A03, 470: A03, 471: A03, 564: A03, 610: A03, 643: A03,
    644: A03, 652: A03, 917: A03, 943: A03,
    # A04 Insecure Design
    73: A04, 183: A04, 213: A04, 235: A04, 256: A04, 257: A04, 266: A04,
    269: A04, 280: A04, 419: A04, 430: A04, 434: A04, 444: A04, 451: A04,
    472: A04, 501: A04, 525: A04, 539: A04, 579: A04, 598: A04, 602: A04,
    642: A04, 646: A04, 650: A04, 653: A04, 656: A04, 657: A04, 799: A04,
    807: A04, 840: A04, 841: A04, 927: A04, 1021: A04, 1173: A04,
    400: A04, 770: A04,  # not listed by OWASP; resource limits are a design concern
    # A05 Security Misconfiguration
    2: A05, 11: A05, 13: A05, 15: A05, 16: A05, 260: A05, 520: A05, 526: A05,
    537: A05, 541: A05, 547: A05, 611: A05, 614: A05, 756: A05, 776: A05,
    942: A05, 1004: A05, 1032: A05, 1174: A05,
    209: A05,  # deviation; error-message disclosure reads as misconfiguration
    489: A05, 693: A05, 923: A05,  # not listed by OWASP
    # A06 Vulnerable and Outdated Components
    937: A06, 1035: A06, 1104: A06,
    # A07 Identification and Authentication Failures
    255: A07, 259: A07, 287: A07, 288: A07, 290: A07, 294: A07, 295: A07,
    297: A07, 300: A07, 302: A07, 304: A07, 306: A07, 307: A07, 346: A07,
    384: A07, 521: A07, 613: A07, 620: A07, 640: A07, 798: A07, 940: A07,
    1216: A07,
    308: A07, 522: A07, 1392: A07,  # not listed by OWASP; credential weaknesses
    # A08 Software and Data Integrity Failures
    345: A08, 353: A08, 426: A08, 494: A08, 502: A08, 565: A08, 784: A08,
    829: A08, 830: A08, 915: A08,
    # A09 Security Logging and Monitoring Failures
    117: A09, 223: A09, 532: A09, 778: A09,
    # A10 Server-Side Request Forgery
    918: A10,
}


# Used only when a finding carries no usable CWE.
OWASP_BY_STRIDE: Dict[str, str] = {
    'Spoofing': A07,
    'Tampering': A03,
    'Repudiation': A09,
    'Information Disclosure': A01,
    'Denial of Service': A04,
    'Elevation of Privilege': A01,
    'Injection': A03,
}


def _cwe_number(value: object) -> Optional[int]:
    text = str(value or '').strip().upper()
    if text.startswith('CWE-'):
        text = text[4:]
    return int(text) if text.isdigit() else None


def owasp_for(cwes: Iterable[object], category: Optional[str] = None) -> List[str]:
    """Resolve OWASP Top 10 (2021) categories for a finding's CWEs.

    Order follows the order the CWEs were supplied, so the rule's primary CWE
    determines the primary category. Falls back to the STRIDE category, and
    finally to misconfiguration only when nothing else is known.
    """
    resolved: List[str] = []
    for cwe in cwes or []:
        number = _cwe_number(cwe)
        mapped = OWASP_2021_BY_CWE.get(number) if number is not None else None
        if mapped and mapped not in resolved:
            resolved.append(mapped)
    if resolved:
        return resolved
    fallback = OWASP_BY_STRIDE.get(str(category or '').strip())
    return [fallback] if fallback else [A05]
