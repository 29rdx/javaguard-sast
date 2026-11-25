package com.javaguard.sast;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class SqlInjectionRuleTest {

    private final SqlInjectionRule rule = new SqlInjectionRule();

    @Test
    void detectsDynamicSqlConcatenationInExecuteQuery() {
        String code = """
            public User findUser(Statement stmt, String username) throws SQLException {
                return stmt.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");
            }
            """;
        List<SecurityFinding> findings = rule.scan("UserDao.java", code);
        assertEquals(1, findings.size());
        assertEquals("JG-SQLI-001", findings.get(0).ruleId());
        assertEquals("CRITICAL", findings.get(0).severity());
        assertEquals(2, findings.get(0).lineNumber());
    }

    @Test
    void allowsParameterizedPreparedStatement() {
        String code = """
            public User findUser(Connection conn, String username) throws SQLException {
                PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
                ps.setString(1, username);
                return ps.executeQuery();
            }
            """;
        List<SecurityFinding> findings = rule.scan("UserDao.java", code);
        assertTrue(findings.isEmpty());
    }
}
