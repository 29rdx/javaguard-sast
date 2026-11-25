package com.javaguard.sast;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class WeakCryptoRuleTest {

    private final WeakCryptoRule rule = new WeakCryptoRule();

    @Test
    void detectsMd5DigestAndAesEcbCipher() {
        String code = """
            MessageDigest md = MessageDigest.getInstance("MD5");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            """;
        List<SecurityFinding> findings = rule.scan("CryptoUtil.java", code);
        assertEquals(2, findings.size());
        assertEquals("JG-CRYPTO-004", findings.get(0).ruleId());
        assertEquals("HIGH", findings.get(1).severity());
    }

    @Test
    void allowsSha256AndAesGcm() {
        String code = """
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            """;
        List<SecurityFinding> findings = rule.scan("CryptoUtil.java", code);
        assertTrue(findings.isEmpty());
    }
}
