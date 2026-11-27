package com.javaguard.sast;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class JavaGuardCliTest {

    @Test
    void scansDirectoryWritesSarifAndReturnsExitCode1OnFindings(@TempDir Path tempDir) throws IOException {
        Path vulnFile = tempDir.resolve("Unsafe.java");
        Files.writeString(vulnFile, "MessageDigest.getInstance(\"MD5\");\nString k = \"AKIAIOSFODNN7EXAMPLE\";\n");
        Path sarifFile = tempDir.resolve("report.sarif");

        int exitCode = JavaGuardCli.run(tempDir, sarifFile);
        assertEquals(1, exitCode);
        String sarif = Files.readString(sarifFile);
        assertTrue(sarif.contains("\"JG-SECRETS-005\""));
    }

    @Test
    void returnsZeroOnCleanJavaDirectory(@TempDir Path tempDir) throws IOException {
        Files.writeString(tempDir.resolve("Clean.java"), "public class Clean { int x = 1; }\n");
        assertEquals(0, JavaGuardCli.run(tempDir, null));
    }
}
