import hashlib
import os
import re
import zipfile
from typing import Any


class StaticAnalyzer:
    """
    Performs static analysis on Android APK archives.
    Parses AndroidManifest, extracts strings, identifies suspicious permissions,
    detects obfuscation and dynamic loading, executes YARA-style heuristic signatures,
    and identifies fraud/banking-trojan patterns.
    """

    DANGEROUS_PERMISSIONS = {
        "android.permission.RECEIVE_SMS": {"severity": "CRITICAL", "desc": "Allows application to intercept incoming SMS messages (used for OTP theft)."},
        "android.permission.READ_SMS": {"severity": "CRITICAL", "desc": "Allows reading stored SMS messages and 2FA authentication codes."},
        "android.permission.SEND_SMS": {"severity": "HIGH", "desc": "Allows stealthily sending SMS messages to premium rate numbers or C2."},
        "android.permission.BIND_ACCESSIBILITY_SERVICE": {"severity": "CRITICAL", "desc": "Allows hijacking screen content, capturing keystrokes, and automated overlay clicks."},
        "android.permission.SYSTEM_ALERT_WINDOW": {"severity": "HIGH", "desc": "Allows drawing phishing overlay windows on top of legitimate banking apps."},
        "android.permission.REQUEST_INSTALL_PACKAGES": {"severity": "HIGH", "desc": "Allows silently installing dropped secondary malware payloads."},
        "android.permission.READ_CONTACTS": {"severity": "HIGH", "desc": "Allows harvesting address book contacts for extortion or worm propagation."},
        "android.permission.READ_PHONE_STATE": {"severity": "MEDIUM", "desc": "Allows reading IMSI, IMEI, and SIM serial number for device fingerprinting."},
        "android.permission.RECORD_AUDIO": {"severity": "HIGH", "desc": "Allows covert background audio recording and eavesdropping."},
        "android.permission.CAMERA": {"severity": "HIGH", "desc": "Allows capturing photos/video without user consent."},
        "android.permission.ACCESS_FINE_LOCATION": {"severity": "MEDIUM", "desc": "Allows tracking precise real-time physical GPS coordinates."},
        "android.permission.QUERY_ALL_PACKAGES": {"severity": "MEDIUM", "desc": "Allows discovering installed banking, crypto, and payment apps on device."},
        "android.permission.INTERNET": {"severity": "LOW", "desc": "Allows opening network sockets to communicate with external servers."},
        "android.permission.RECEIVE_BOOT_COMPLETED": {"severity": "MEDIUM", "desc": "Allows malware persistence by auto-starting upon device reboot."},
        "android.permission.USE_BIOMETRIC": {"severity": "HIGH", "desc": "Allows intercepting biometric authentication prompts."}
    }

    YARA_SIGNATURES = [
        {
            "name": "Android_Banking_Trojan_Overlay_Injector",
            "threat_family": "SharkBot / TeaBot / FakeSBI",
            "severity": "CRITICAL",
            "description": "Detects presence of Accessibility abuse, package enumeration, and window overlay injection logic.",
            "patterns": [r"SYSTEM_ALERT_WINDOW", r"AccessibilityService", r"FLAG_NOT_TOUCHABLE|FLAG_NOT_FOCUSABLE", r"AccessibilityNodeInfo"]
        },
        {
            "name": "Android_SMS_OTP_Harvester",
            "threat_family": "SMSThief / FakeUPI Harvester",
            "severity": "CRITICAL",
            "description": "Detects incoming SMS broadcast receivers paired with HTTP upload or Telegram Bot C2 forwarding.",
            "patterns": [r"android\.provider\.Telephony\.SMS_RECEIVED", r"getDisplayMessageBody|getOriginatingAddress", r"api\.telegram\.org/bot|https?://[\w\.-]+/api/sms"]
        },
        {
            "name": "Android_LoanShark_Extortion_Spyware",
            "threat_family": "SpyLoan / FastCash Syndicate",
            "severity": "HIGH",
            "description": "Detects aggressive harvesting of device contacts, call logs, SMS, and photo gallery metadata.",
            "patterns": [r"ContactsContract", r"CallLog\.Calls", r"content://sms/inbox", r"uploadContacts|syncDeviceData"]
        },
        {
            "name": "Android_Dynamic_Payload_Dropper",
            "threat_family": "Dropper / Loader",
            "severity": "HIGH",
            "description": "Detects runtime reflection, dynamic DEX loading, and encrypted asset extraction.",
            "patterns": [r"DexClassLoader|InMemoryDexClassLoader", r"Class\.forName\(", r"AES/CBC/PKCS5Padding|Base64\.decode"]
        }
    ]

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.extracted_strings: list[str] = []
        self.extracted_urls: list[str] = []
        self.extracted_ips: list[str] = []
        self.permissions: list[str] = []
        self.manifest_details: dict[str, Any] = {}
        self.obfuscation_indicators: list[str] = []
        self.matched_yara_rules: list[dict[str, Any]] = []
        self.fraud_heuristics: list[dict[str, Any]] = []

    def analyze(self) -> dict[str, Any]:
        """Execute full static analysis pipeline."""
        if not os.path.exists(self.apk_path):
            raise FileNotFoundError(f"APK file not found at: {self.apk_path}")

        # 1. Compute file hashes
        hashes = self._calculate_hashes()

        # 2. Extract contents from ZIP/APK
        self._inspect_apk_zip()

        # 3. Analyze permissions
        perm_findings = self._evaluate_permissions()

        # 4. Check for Obfuscation & Dynamic Loading
        obfuscation_findings = self._detect_obfuscation()

        # 5. Execute YARA & Heuristic signatures
        yara_findings = self._evaluate_yara_signatures()

        # 6. Evaluate Fraud Specific Patterns
        fraud_findings = self._detect_fraud_patterns()

        return {
            "hashes": hashes,
            "manifest": self.manifest_details,
            "permissions": self.permissions,
            "permission_findings": perm_findings,
            "extracted_urls": self.extracted_urls,
            "extracted_ips": self.extracted_ips,
            "obfuscation_indicators": obfuscation_findings,
            "yara_matches": yara_findings,
            "fraud_heuristics": fraud_findings,
            "extracted_strings_sample": self.extracted_strings[:100]
        }

    def _calculate_hashes(self) -> dict[str, str]:
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        with open(self.apk_path, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
                md5_hash.update(byte_block)
        return {
            "sha256": sha256_hash.hexdigest(),
            "md5": md5_hash.hexdigest(),
            "file_size": os.path.getsize(self.apk_path)
        }

    def _inspect_apk_zip(self):
        """Extract strings, manifest clues, and resources from APK archive."""
        all_raw_bytes = bytearray()
        try:
            with zipfile.ZipFile(self.apk_path, "r") as z:
                namelist = z.namelist()
                any(name.endswith(".dex") for name in namelist)

                self.manifest_details["dex_files"] = [n for n in namelist if n.endswith(".dex")]
                self.manifest_details["native_libraries"] = [n for n in namelist if n.startswith("lib/")]
                self.manifest_details["assets"] = [n for n in namelist if n.startswith("assets/")]

                # Read dex and manifest files
                for item in namelist:
                    if item.endswith(".dex") or item == "AndroidManifest.xml" or item.endswith(".json") or item.endswith(".txt"):
                        try:
                            content = z.read(item)
                            all_raw_bytes.extend(content)
                        except Exception:
                            pass
        except zipfile.BadZipFile:
            with open(self.apk_path, "rb") as f:
                all_raw_bytes = f.read()

        # String extraction (printable ASCII / UTF-8 strings >= 4 chars)
        extracted = re.findall(rb"[\x20-\x7e]{4,}", all_raw_bytes)
        string_set = set()
        for b in extracted:
            try:
                s = b.decode("utf-8", errors="ignore").strip()
                if len(s) >= 4 and not s.startswith("META-INF"):
                    string_set.add(s)
            except Exception:
                pass

        self.extracted_strings = sorted(list(string_set))

        # URL extraction
        url_pattern = re.compile(r"https?://(?:[a-zA-Z0-9_\-\.]+(?:\.[a-zA-Z]{2,})|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?(?:/[^\s\"'<>]*)?")
        ip_pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")

        raw_text = " \n ".join(self.extracted_strings)
        self.extracted_urls = list(set(url_pattern.findall(raw_text)))
        self.extracted_ips = list(set([ip for ip in ip_pattern.findall(raw_text) if not ip.startswith("127.") and not ip.startswith("0.") and not ip.startswith("255.")]))

        # Permission extraction
        for s in self.extracted_strings:
            if "android.permission." in s:
                perm_match = re.search(r"(android\.permission\.[A-Z0-9_]+)", s)
                if perm_match:
                    self.permissions.append(perm_match.group(1))

        self.permissions = sorted(list(set(self.permissions)))

        # Manifest metadata heuristic
        pkg_match = re.search(r"package=[\"']([a-zA-Z0-9_\.]+)[\"']", raw_text)
        if pkg_match:
            self.manifest_details["package_name"] = pkg_match.group(1)
        else:
            # Look for common package patterns in strings
            pkgs = [s for s in self.extracted_strings if re.match(r"^com\.[a-z0-9_]+\.[a-z0-9_]+", s)]
            self.manifest_details["package_name"] = pkgs[0] if pkgs else "com.suspicious.app"

        self.manifest_details["extracted_permission_count"] = len(self.permissions)
        self.manifest_details["exported_components_detected"] = len([s for s in self.extracted_strings if "android:exported=\"true\"" in s or "exported" in s])

    def _evaluate_permissions(self) -> list[dict[str, Any]]:
        findings = []
        for perm in self.permissions:
            if perm in self.DANGEROUS_PERMISSIONS:
                info = self.DANGEROUS_PERMISSIONS[perm]
                findings.append({
                    "permission": perm,
                    "severity": info["severity"],
                    "description": info["desc"],
                    "category": "SUSPICIOUS_PERMISSION"
                })
        return findings

    def _detect_obfuscation(self) -> list[dict[str, Any]]:
        indicators = []
        raw_text = " \n ".join(self.extracted_strings)

        if "DexClassLoader" in raw_text or "InMemoryDexClassLoader" in raw_text:
            indicators.append({
                "type": "DYNAMIC_CODE_LOADING",
                "severity": "HIGH",
                "evidence": "DexClassLoader / InMemoryDexClassLoader detected in dex strings",
                "description": "App dynamically unpacks and loads secondary executable code at runtime to evade static inspection."
            })

        if "Class.forName" in raw_text and ("getMethod" in raw_text or "invoke" in raw_text):
            indicators.append({
                "type": "REFLECTION_EVASION",
                "severity": "MEDIUM",
                "evidence": "Java Reflection (Class.forName + invoke) found",
                "description": "App utilizes runtime reflection to obscure invoked dangerous APIs and hide malicious functionality."
            })

        if any("lib/" in n for n in self.manifest_details.get("native_libraries", [])):
            indicators.append({
                "type": "NATIVE_CODE_EXECUTION",
                "severity": "INFO",
                "evidence": f"Native C/C++ libraries found: {', '.join(self.manifest_details.get('native_libraries', [])[:3])}",
                "description": "App embeds compiled native ELF binaries which may conceal unpackers or C2 communication."
            })

        if "Base64.decode" in raw_text and ("AES" in raw_text or "DES" in raw_text or "Cipher" in raw_text):
            indicators.append({
                "type": "ENCRYPTED_PAYLOAD_STRINGS",
                "severity": "HIGH",
                "evidence": "Cryptographic Cipher with Base64 decode routines detected",
                "description": "Strings, C2 endpoints, or payload URLs are encrypted in assets/resources and decrypted at runtime."
            })

        return indicators

    def _evaluate_yara_signatures(self) -> list[dict[str, Any]]:
        matches = []
        raw_text = " \n ".join(self.extracted_strings)

        for sig in self.YARA_SIGNATURES:
            matched_patterns = []
            for pat in sig["patterns"]:
                if re.search(pat, raw_text, re.IGNORECASE):
                    matched_patterns.append(pat)

            # Match if at least 2 patterns hit (or all if < 2)
            req_hits = min(2, len(sig["patterns"]))
            if len(matched_patterns) >= req_hits:
                matches.append({
                    "rule_name": sig["name"],
                    "threat_family": sig["threat_family"],
                    "severity": sig["severity"],
                    "description": sig["description"],
                    "matched_patterns": matched_patterns,
                    "confidence": f"{int((len(matched_patterns) / len(sig['patterns'])) * 100)}%"
                })
        return matches

    def _detect_fraud_patterns(self) -> list[dict[str, Any]]:
        fraud_hits = []
        raw_text = " \n ".join(self.extracted_strings).lower()

        # 1. Overlay & Accessibility Hijack Pattern
        if ("accessibility" in raw_text or "bind_accessibility_service" in raw_text) and ("overlay" in raw_text or "system_alert_window" in raw_text):
            fraud_hits.append({
                "pattern": "ACCESSIBILITY_OVERLAY_HIJACKING",
                "severity": "CRITICAL",
                "title": "Overlay Attack & Accessibility Service Hijacking",
                "description": "Application requests both Accessibility permissions and System Alert Window, a hallmark signature of banking trojans (SharkBot/TeaBot) used to inject fake login overlays over banking/UPI apps."
            })

        # 2. Indian Banking & UPI Phishing Target Strings
        banking_keywords = ["sbi", "yono", "hdfc", "icici", "paytm", "phonepe", "gpay", "mpin", "debit card", "cvv", "netbanking", "otp"]
        matched_kw = [kw for kw in banking_keywords if kw in raw_text]
        if len(matched_kw) >= 3:
            fraud_hits.append({
                "pattern": "FINANCIAL_IMPERSONATION_TARGETS",
                "severity": "HIGH",
                "title": "Banking / UPI Institution Targeting",
                "description": f"Contains hardcoded targets and keywords matching financial applications: {', '.join(matched_kw)}."
            })

        # 3. Telegram / C2 Bot Exfiltration
        if "api.telegram.org/bot" in raw_text:
            fraud_hits.append({
                "pattern": "TELEGRAM_C2_EXFILTRATION",
                "severity": "CRITICAL",
                "title": "Telegram Bot API Command & Control Channel",
                "description": "Hardcoded Telegram bot API tokens found for exfiltrating victim credentials, OTPs, and SMS messages directly to threat actor chat groups."
            })

        return fraud_hits
