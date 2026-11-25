package com.javaguard.sast;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class SecretsAndTlsRuleTest {

    private final JavaGuardScanner scanner = new JavaGuardScanner();

    @Test
    void detectsHardcodedAwsKeyAndTrustAllTls() {
        String code = """
            String awsKey = "AKIAIOSFODNN7EXAMPLE";
            class InsecureTrust implements X509TrustManager {
            }
            """;
        List<SecurityFinding> findings = scanner.scanSource("Config.java", code);
        assertEquals(2, findings.size());
        assertEquals("JG-SECRETS-005", findings.get(0).ruleId());
        assertEquals("JG-TLS-006", findings.get(1).ruleId());
    }

    @Test
    void allowsEnvPlaceholderAndCleanCode() {
        String code = """
            String apiKey = "${API_KEY}";
            """;
        List<SecurityFinding> findings = scanner.scanSource("Config.java", code);
        assertTrue(findings.isEmpty());
    }
}
