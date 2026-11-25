# JavaGuard SAST (`javaguard-sast`)

Lightweight Static Application Security Testing (SAST) & Security Rule Engine for Java 21+ applications.

## Security Rules
- **JG-SQLI-001**: Detects dynamic SQL string concatenation in `Statement.execute*` and JDBC templates.
- **JG-XXE-002**: Flags `DocumentBuilderFactory` / `SAXParserFactory` missing `disallow-doctype-decl`.
- **JG-DESER-003**: Detects unsafe `ObjectInputStream.readObject()` without `ObjectInputFilter`.
- **JG-CRYPTO-004**: Flags weak `MessageDigest` (`MD5`, `SHA-1`) and `Cipher` (`ECB`, `DES`) usage.
- **JG-SECRETS-005**: High-entropy API key, AWS access key, and hardcoded password scanner.
- **JG-TLS-006**: Detects permissive `X509TrustManager` and `HostnameVerifier` TLS bypasses.

## Build & Test
```bash
mvn test
```
