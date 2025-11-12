# DIY Code Signing with AWS KMS and AWS Private CA

This sample demonstrates code signing using AWS KMS and AWS Private CA with support for RSA, ECC, and ML-DSA algorithms. It generates RFC 5652 compliant CMS (Cryptographic Message Syntax) detached signatures in .p7s format compatible with standard cryptographic tools.

## Instructions

1. Ensure that you have set up credentials per <https://docs.aws.amazon.com/sdk-for-java/latest/developer-guide/credentials.html>

2. The credentials used should have permissions to invoke both AWS Private CA and AWS KMS APIs. You can use the following managed policies or create custom policies with least privilege:

   **Managed Policies:**
   - `AWSCertificateManagerPrivateCAFullAccess` - For AWS Private CA operations
   - `AWSKeyManagementServicePowerUser` - For AWS KMS operations

   **Example Custom Policy (Least Privilege):**

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "acm-pca:CreateCertificateAuthority",
           "acm-pca:DescribeCertificateAuthority",
           "acm-pca:GetCertificateAuthorityCertificate",
           "acm-pca:ListCertificateAuthorities",
           "acm-pca:GetCertificateAuthorityCsr",
           "acm-pca:GetCertificate",
           "acm-pca:IssueCertificate",
           "acm-pca:ImportCertificateAuthorityCertificate"
         ],
         "Resource": "*"
       },
       {
         "Effect": "Allow",
         "Action": [
           "kms:CreateKey",
           "kms:CreateAlias",
           "kms:ListAliases",
           "kms:GetPublicKey",
           "kms:Sign"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

   For more information, see:
   - [AWS Private CA Authentication and Access Control](https://docs.aws.amazon.com/privateca/latest/userguide/granting-ca-access.html)
   - [AWS KMS Authentication and Access Control](https://docs.aws.amazon.com/kms/latest/developerguide/control-access.html)

3. Make sure that maven is installed on your system. Maven needs JDK installed as a prerequisite. You can install maven by following the instructions here :

<https://maven.apache.org/install.html>

At least JDK version 11 is needed for the code to execute successfully.

4. For executing the code, you can use the commands below in the directory where the git repo is cloned

## Usage

### Basic Usage

```bash
mvn verify
```

This runs the code signing example using the default file (`target/diy-code-signing-kms-private-ca-1.0-SNAPSHOT.jar`) and algorithm (`RSA2048`). It should build and execute the code while showing you printouts for the various steps involved.

### Easy Way to Run (Recommended)

Use the provided shell script for a simpler experience:

```bash
# Run with defaults (signs README.md using RSA2048)
./run.sh

# Specify a file to sign (signs with RSA2048)
./run.sh myfile.jar

# Specify both file and algorithm
./run.sh myfile.jar MLDSA65
```

### Alternative: Direct Maven Command

You can also run directly with Maven if preferred:

```bash
mvn exec:java -Dexec.args="/path/to/file RSA2048"
```

### Supported Algorithms

The following algorithms are supported:

**RSA:**

- `RSA2048` - RSA 2048-bit keys with SHA-256 (default)
- `RSA3072` - RSA 3072-bit keys with SHA-384
- `RSA4096` - RSA 4096-bit keys with SHA-512

**ECC:**

- `ECP256` - NIST P-256 curve with SHA-256
- `ECP384` - NIST P-384 curve with SHA-384
- `ECP521` - NIST P-521 curve with SHA-512

**ML-DSA:**

- `MLDSA44` - ML-DSA-44 with SHAKE-256
- `MLDSA65` - ML-DSA-65 with SHAKE-256
- `MLDSA87` - ML-DSA-87 with SHAKE-256

### Algorithm Mapping Reference

| Algorithm Name | KMS KeySpec | KMS SigningAlgorithm | PCA KeyAlgorithm | PCA SigningAlgorithm | BouncyCastle Algorithm |
|-------------|-------------|---------------------|------------------|---------------------|----------------------|
| RSA2048 | RSA_2048 | RSASSA_PKCS1_V1_5_SHA_256 | RSA_2048 | SHA256WITHRSA | SHA256WITHRSA |
| RSA3072 | RSA_3072 | RSASSA_PKCS1_V1_5_SHA_384 | RSA_3072 | SHA384WITHRSA | SHA384WITHRSA |
| RSA4096 | RSA_4096 | RSASSA_PKCS1_V1_5_SHA_512 | RSA_4096 | SHA512WITHRSA | SHA512WITHRSA |
| ECP256 | ECC_NIST_P256 | ECDSA_SHA_256 | EC_prime256v1 | SHA256WITHECDSA | SHA256WITHECDSA |
| ECP384 | ECC_NIST_P384 | ECDSA_SHA_384 | EC_secp384r1 | SHA384WITHECDSA | SHA384WITHECDSA |
| ECP521 | ECC_NIST_P521 | ECDSA_SHA_512 | EC_secp521r1 | SHA512WITHECDSA | SHA512WITHECDSA |
| MLDSA44 | ML_DSA_44 | ML_DSA_SHAKE_256 | ML_DSA_44 | ML_DSA_44 | ML-DSA-44 |
| MLDSA65 | ML_DSA_65 | ML_DSA_SHAKE_256 | ML_DSA_65 | ML_DSA_65 | ML-DSA-65 |
| MLDSA87 | ML_DSA_87 | ML_DSA_SHAKE_256 | ML_DSA_87 | ML_DSA_87 | ML-DSA-87 |

## Output

Two files are created per run:

1. `signature-{ALGORITHM}.p7s` - Detached CMS signature (binary DER format)
2. `root-ca-{ALGORITHM}.pem` - Root CA certificate for verification

The original file specified in the command line arguments is used as the source of truth for signing and verification.

### Example output files after running: `./run.sh myfile.jar RSA2048`

```
signature-RSA2048.p7s       # Detached CMS signature
root-ca-RSA2048.pem         # Root CA certificate for verification
```

### Verifying Signatures with Standard Tools

You can verify the generated signatures using OpenSSL:

```bash
openssl cms -verify -in signature-RSA2048.p7s -content target/diy-code-signing-kms-private-ca-1.0-SNAPSHOT.jar -CAfile root-ca-RSA2048.pem -inform DER -purpose any -binary -out /dev/null
```

For other files and algorithms:

```bash
openssl cms -verify -in signature-ECP256.p7s -content myfile.jar -CAfile root-ca-ECP256.pem -inform DER -purpose any -binary -out /dev/null
openssl cms -verify -in signature-MLDSA44.p7s -content document.pdf -CAfile root-ca-MLDSA44.pem -inform DER -purpose any -binary -out /dev/null
```

## Production Considerations

### Trust Store Implementation

This sample code uses a simplified trust store implementation for demonstration purposes. The root CA certificate is stored in a Java class instance rather than a proper trust store. 

**For production use, you should:**

1. **Implement secure trust stores** - Store root CA certificates in secure, tamper-resistant trust stores rather than in-memory objects
2. **Use established trust store formats** - Consider using standard trust store formats like JKS, PKCS#12, or system trust stores
3. **Implement proper certificate validation** - Include full certificate chain validation, CRL checking, and OCSP validation as appropriate
4. **Secure key management** - Ensure AWS KMS keys have appropriate access controls and are properly managed
5. **Certificate lifecycle management** - Implement proper certificate rotation, renewal, and revocation processes

The current implementation stores the root CA certificate in the `PrivateCA` class instance to avoid additional AWS Private CA API calls during verification. In production, you would typically retrieve certificates from a secure trust store or certificate management system.

Successful verification will display "CMS Verification successful" and return exit code 0.

## Cleanup

### AWS Resources

If you do execute the code and do not perform the clean up, you will be accruing costs for the AWS Private CA's that has been setup. Please delete the CA's by going into the AWS Certificate Manager Private CA on the AWS console. Please note that the CA needs to be disabled before you can delete it. Also delete the asymmetric KMS key that was created, you can do this from the AWS KMS service on the AWS console.

You can follow the instructions at the link below :

<https://docs.aws.amazon.com/acm-pca/latest/userguide/PCADeleteCA.html>

### Generated Files

The code execution will create several files in your working directory:

- `signature-{ALGORITHM}.p7s` - CMS signature files  
- `root-ca-{ALGORITHM}.pem` - Root CA certificate files

You can safely delete these files after testing. They are regenerated on each run.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.

## Contributing & Security

See [CONTRIBUTING](CONTRIBUTING.md) for more information.

**Note:** Sample code, software libraries, command line tools, proofs of concept, templates, or other related technology are provided as AWS Content or Third-Party Content under the AWS Customer Agreement, or the relevant written agreement between you and AWS (whichever applies). You should not use this AWS Content or Third-Party Content in your production accounts, or on production or other critical data. You are responsible for testing, securing, and optimizing the AWS Content or Third-Party Content, such as sample code, as appropriate for production grade use based on your specific quality control practices and standards. Deploying AWS Content or Third-Party Content may incur AWS charges for creating or using AWS chargeable resources, such as creating AWS Private CA Certificate Authorities and AWS KMS CMKs.
