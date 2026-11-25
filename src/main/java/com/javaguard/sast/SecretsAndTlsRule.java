package com.javaguard.sast;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects hardcoded API keys / AWS credentials and permissive X509TrustManager
 * or HostnameVerifier TLS verification bypasses.
 */
public class SecretsAndTlsRule implements SecurityRule {

    private static final Pattern AWS_KEY_PATTERN = Pattern.compile("AKIA[0-9A-Z]{16}");
    private static final Pattern HARDCODED_SECRET = Pattern.compile(
        "(?i)(api_key|secret_key|password|private_token)\\s*=\\s*\"([^\"]{12,})\""
    );
    private static final Pattern TRUST_ALL_TLS = Pattern.compile(
        "(implements\\s+X509TrustManager|HostnameVerifier\\s*\\(\\)\\s*->\\s*true|verify\\s*\\([^)]*\\)\\s*\\{\\s*return\\s+true)"
    );

    @Override
    public String ruleId() {
        return "JG-SEC-TLS-005";
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
            if (AWS_KEY_PATTERN.matcher(lines[i]).find()) {
                findings.add(new SecurityFinding(
                    "JG-SECRETS-005",
                    "CRITICAL",
                    fileName,
                    i + 1,
                    "Hardcoded AWS Access Key ID detected in source code.",
                    "[REDACTED_AWS_KEY]"
                ));
            } else {
                Matcher sec = HARDCODED_SECRET.matcher(lines[i]);
                if (sec.find() && !sec.group(2).contains("${")) {
                    findings.add(new SecurityFinding(
                        "JG-SECRETS-005",
                        "HIGH",
                        fileName,
                        i + 1,
                        "Hardcoded credential literal assigned to '" + sec.group(1) + "'.",
                        sec.group(1) + " = \"[REDACTED]\""
                    ));
                }
            }
            if (TRUST_ALL_TLS.matcher(lines[i]).find()) {
                findings.add(new SecurityFinding(
                    "JG-TLS-006",
                    "CRITICAL",
                    fileName,
                    i + 1,
                    "Permissive TLS TrustManager/HostnameVerifier disables certificate validation (MITM risk).",
                    trimmed
                ));
            }
        }
        return findings;
    }
}
