package com.javaguard.sast;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects dynamic SQL string concatenation inside JDBC Statement.execute*
 * and Spring JdbcTemplate calls (OWASP A03:2021 Injection).
 */
public class SqlInjectionRule implements SecurityRule {

    private static final Pattern SQL_CONCAT_PATTERN = Pattern.compile(
        "(executeQuery|executeUpdate|execute|queryForObject|query)\\s*\\(\\s*\"[^\"]*\\b(SELECT|INSERT|UPDATE|DELETE)\\b[^\"]*\"\\s*\\+",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern VAR_SQL_CONCAT = Pattern.compile(
        "(String\\s+\\w+\\s*=\\s*\"[^\"]*\\b(SELECT|INSERT|UPDATE|DELETE)\\b[^\"]*\"\\s*\\+)",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public String ruleId() {
        return "JG-SQLI-001";
    }

    @Override
    public List<SecurityFinding> scan(String fileName, String sourceCode) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (sourceCode == null || sourceCode.isBlank()) {
            return findings;
        }
        String[] lines = sourceCode.split("\\R");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String trimmed = line.trim();
            if (trimmed.startsWith("//") || trimmed.startsWith("*")) {
                continue;
            }
            Matcher m1 = SQL_CONCAT_PATTERN.matcher(line);
            Matcher m2 = VAR_SQL_CONCAT.matcher(line);
            if (m1.find() || m2.find()) {
                findings.add(new SecurityFinding(
                    ruleId(),
                    "CRITICAL",
                    fileName,
                    i + 1,
                    "Dynamic SQL string concatenation detected; use PreparedStatement parameterized queries.",
                    trimmed
                ));
            }
        }
        return findings;
    }
}
