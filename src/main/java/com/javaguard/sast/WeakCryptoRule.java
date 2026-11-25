package com.javaguard.sast;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Flags weak cryptographic algorithms in MessageDigest (MD5, SHA-1)
 * and Cipher (ECB mode, DES/DESede, RC4) (OWASP A02:2021).
 */
public class WeakCryptoRule implements SecurityRule {

    private static final Pattern WEAK_DIGEST = Pattern.compile(
        "MessageDigest\\.getInstance\\s*\\(\\s*\"(MD5|SHA-?1|MD2)\"\\s*\\)",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern WEAK_CIPHER = Pattern.compile(
        "Cipher\\.getInstance\\s*\\(\\s*\"([^\"]*/ECB/[^\"]*|DES[^\"]*|RC4|Blowfish|AES)\"\\s*\\)",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public String ruleId() {
        return "JG-CRYPTO-004";
    }

    @Override
    public List<SecurityFinding> scan(String fileName, String sourceCode) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (sourceCode == null || sourceCode.isBlank()) {
            return findings;
        }
        String[] lines = sourceCode.split("\\R");
        for (int i = 0; i < lines.length; i++) {
            String trimmed = lines[i].trim();
            if (trimmed.startsWith("//") || trimmed.startsWith("*")) {
                continue;
            }
            Matcher d = WEAK_DIGEST.matcher(lines[i]);
            if (d.find()) {
                findings.add(new SecurityFinding(
                    ruleId(),
                    "MEDIUM",
                    fileName,
                    i + 1,
                    "Weak hash algorithm (" + d.group(1) + "); migrate to SHA-256 or SHA-3.",
                    trimmed
                ));
            }
            Matcher c = WEAK_CIPHER.matcher(lines[i]);
            if (c.find()) {
                findings.add(new SecurityFinding(
                    ruleId(),
                    "HIGH",
                    fileName,
                    i + 1,
                    "Insecure cipher transformation (" + c.group(1) + "); use AES/GCM/NoPadding.",
                    trimmed
                ));
            }
        }
        return findings;
    }
}
