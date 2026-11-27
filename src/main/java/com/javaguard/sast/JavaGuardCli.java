package com.javaguard.sast;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Recursive CLI scanner for JavaGuard SAST.
 * Walks .java files in a target directory, runs all security rules,
 * optionally writes SARIF 2.1.0 output, and returns exit code 1 on CRITICAL/HIGH findings.
 */
public class JavaGuardCli {

    public static int run(Path targetDir, Path sarifOut) throws IOException {
        JavaGuardScanner scanner = new JavaGuardScanner();
        List<SecurityFinding> findings = new ArrayList<>();

        try (Stream<Path> walk = Files.walk(targetDir)) {
            List<Path> javaFiles = walk
                .filter(Files::isRegularFile)
                .filter(p -> p.toString().endsWith(".java"))
                .sorted()
                .toList();

            for (Path file : javaFiles) {
                String content = Files.readString(file);
                String relPath = targetDir.relativize(file).toString();
                findings.addAll(scanner.scanSource(relPath, content));
            }
        }

        if (sarifOut != null) {
            SarifExporter exporter = new SarifExporter();
            Files.writeString(sarifOut, exporter.toSarifJson(findings));
        }

        boolean hasBlocking = findings.stream()
            .anyMatch(f -> "CRITICAL".equalsIgnoreCase(f.severity()) || "HIGH".equalsIgnoreCase(f.severity()));
        return hasBlocking ? 1 : 0;
    }

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            System.err.println("Usage: JavaGuardCli <target-dir> [sarif-out.json]");
            System.exit(2);
        }
        Path target = Path.of(args[0]);
        Path sarif = args.length > 1 ? Path.of(args[1]) : null;
        System.exit(run(target, sarif));
    }
}
