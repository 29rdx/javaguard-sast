package com.javaguard.sast;

import java.util.ArrayList;
import java.util.List;

/**
 * Orchestrates all JavaGuard SAST security rules over Java source files.
 */
public class JavaGuardScanner {

    private final List<SecurityRule> rules;

    public JavaGuardScanner() {
        this.rules = List.of(
            new SqlInjectionRule(),
            new XxeRule(),
            new DeserializationRule(),
            new WeakCryptoRule(),
            new SecretsAndTlsRule()
        );
    }

    public List<SecurityFinding> scanSource(String fileName, String sourceCode) {
        List<SecurityFinding> all = new ArrayList<>();
        for (SecurityRule rule : rules) {
            all.addAll(rule.scan(fileName, sourceCode));
        }
        return all;
    }
}
