package com.amazonaws.acmpcakms.examples;

import com.amazonaws.acmpcakms.examples.Signing.Signature;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.security.cert.*;
import java.util.*;
import java.util.stream.Collectors;

public class CustomCodeSigningObject {

    private static final String CUSTOM_OBJECT_HEADER = "-----BEGIN CUSTOM OBJECT-----\n";
    private static final String CUSTOM_OBJECT_FOOTER = "-----END CUSTOM OBJECT-----\n";

    private final TBSCustomCodeSigningObject tbs;
    private final Signature signature;

    public static CustomCodeSigningObject getInstance(final String pem) {
        String base64 = pem.replace(CUSTOM_OBJECT_HEADER, "")
                .replace(CUSTOM_OBJECT_FOOTER, "")
                .replaceAll("\\n", "")
                .replaceAll("\\r", "");

        byte[] bytes = Base64.getDecoder()
                .decode(base64);

        ASN1Sequence sequence = ASN1Sequence.getInstance(bytes);

        if (sequence.size() != 3) {
            throw new IllegalArgumentException("Unexpected object length (" + sequence.size() + ")");
        }

        TBSCustomCodeSigningObject tbsObject = TBSCustomCodeSigningObject.getInstance((ASN1Sequence) sequence.getObjectAt(0));
        AlgorithmIdentifier signatureAlgorithm = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
        DERBitString signature = (DERBitString) sequence.getObjectAt(2);

        return new CustomCodeSigningObject(tbsObject, new Signature(signatureAlgorithm, signature));
    }

    private CustomCodeSigningObject(final TBSCustomCodeSigningObject tbs, final Signature signature) {
        if (Objects.isNull(tbs)) {
            throw new IllegalArgumentException("A TBS must be specified");
        }

        if (Objects.isNull(signature)) {
            throw new IllegalArgumentException("A signature must be specified");
        }

        this.tbs = tbs;
        this.signature = signature;
    }

    private CustomCodeSigningObject(
            final AsymmetricCMK cmk,
            final byte[] dataBlob,
            final X509CertificateHolder issuerCertificate) throws Exception {

        if (Objects.isNull(cmk)) {
            throw new IllegalArgumentException("A CMK must be specified");
        }

        if (Objects.isNull(dataBlob)) {
            throw new IllegalArgumentException("A data blob must be specified");
        }

        if (Objects.isNull(issuerCertificate)) {
            throw new IllegalArgumentException("A issuer certificate must be specified");
        }

        this.tbs = new TBSCustomCodeSigningObject(dataBlob, issuerCertificate);
        this.signature = Signing.generateSignature(cmk, tbs.getEncoded());
    }

    public void validate(final String rootCertificatePEM, final String certificateChainPEM) throws Exception {
        System.out.println("Validating CustomCodeSigningObject signature against the provided certificate chain");

        X509CertificateHolder rootCertificate = toCertificateHolder(rootCertificatePEM);
        Set<X509Certificate> certificateChain = toCertificates(certificateChainPEM);

        X509CertSelector issuerCertificateSelector = new X509CertSelector();
        issuerCertificateSelector.setSubject(tbs.issuerCertificateSubject.getEncoded());

        CertStore certStore = createCertStore(certificateChain);

        validateCertificateChain(rootCertificate, issuerCertificateSelector, certStore);

        Collection<? extends Certificate> issuerCertificates = certStore.getCertificates(issuerCertificateSelector);

        if (issuerCertificates.size() != 1) {
            throw new IllegalArgumentException("More than 1 certificate found with matching subject");
        }

        Certificate issuerCertificate = new ArrayList<>(issuerCertificates).get(0);

        ContentVerifierProvider contentVerifierProvider = new JcaContentVerifierProviderBuilder().build(issuerCertificate.getPublicKey());
        ContentVerifier contentVerifier = contentVerifierProvider.get(signature.getAlgorithmIdentifier());

        OutputStream outputStream = contentVerifier.getOutputStream();
        outputStream.write(tbs.getEncoded());
        outputStream.close();

        if (!contentVerifier.verify(signature.getSignature().getBytes())) {
            throw new SignatureException("CustomCodeSigningObject signature failed to verify");
        }

        System.out.println("CustomCodeSigningObject signature validated successfully");
    }

    public static void validateCertificateChain(final X509CertificateHolder rootCertificateHolder, final X509CertSelector selector, final CertStore certStore) throws Exception {
        X509Certificate rootCertificate = new JcaX509CertificateConverter().getCertificate(rootCertificateHolder);

        Set<TrustAnchor> trustAnchors = new HashSet<>();
        trustAnchors.add(new TrustAnchor(rootCertificate, null));

        PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustAnchors, selector);
        pkixBuilderParameters.addCertStore(createCertStore(rootCertificate));
        pkixBuilderParameters.addCertStore(certStore);
        pkixBuilderParameters.setRevocationEnabled(false);

        CertPathBuilder builder = CertPathBuilder.getInstance(CertPathBuilder.getDefaultType(), BouncyCastleProvider.PROVIDER_NAME);
        builder.build(pkixBuilderParameters);

        System.out.println("Certificate chain is valid");
    }

    private static CertStore createCertStore(final X509Certificate certificate) throws Exception {
        Set<X509Certificate> certificates = new HashSet<>();
        certificates.add(certificate);
        return createCertStore(certificates);
    }

    private static CertStore createCertStore(final Set<X509Certificate> certificates) throws Exception {
        CollectionCertStoreParameters collectionCertStoreParameters = new CollectionCertStoreParameters(certificates);
        return CertStore.getInstance("Collection", collectionCertStoreParameters, BouncyCastleProvider.PROVIDER_NAME);
    }

    private static ASN1Sequence makeSequence(final ASN1Encodable... asn1Encodables) {
        ASN1EncodableVector outputVector = new ASN1EncodableVector();
        Arrays.asList(asn1Encodables)
                .forEach(outputVector::add);
        return new DERSequence(outputVector);
    }

    private static X509CertificateHolder toCertificateHolder(final String certificate) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return toCertificateHolder(certificateFactory.generateCertificate(new ByteArrayInputStream(certificate.getBytes(StandardCharsets.UTF_8))));
    }

    private static Set<X509Certificate> toCertificates(final String certificateChain) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return certificateFactory.generateCertificates(new ByteArrayInputStream(certificateChain.getBytes(StandardCharsets.UTF_8))).stream()
                .map(X509Certificate.class::cast)
                .collect(Collectors.toSet());
    }

    private static X509CertificateHolder toCertificateHolder(final Certificate certificate) throws Exception {
        return new X509CertificateHolder(certificate.getEncoded());
    }

    @Override
    public String toString() {
        try {
            ASN1Sequence outputSequence = makeSequence(
                    tbs.getASN1Structure(),
                    signature.getAlgorithmIdentifier(),
                    signature.getSignature());

            byte[] outputBytes = outputSequence.getEncoded();

            String outputEncoded = Base64.getEncoder()
                    .encodeToString(outputBytes)
                    .replaceAll("(.{64})", "$1\n")
                    .strip() + "\n";

            String pem = CUSTOM_OBJECT_HEADER + outputEncoded + CUSTOM_OBJECT_FOOTER;

            System.out.println("Generated PEM:\n" + pem);

            return pem;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private AsymmetricCMK cmk;
        private byte[] dataBlob;
        private X509CertificateHolder issuerCertificate;

        private Builder() {}

        public Builder withAsymmetricCMK(final AsymmetricCMK cmk) {
            this.cmk = cmk;
            return this;
        }

        public Builder withDataBlob(final byte[] dataBlob) {
            this.dataBlob = dataBlob;
            return this;
        }

        public Builder withCertificate(final String issuer) throws Exception {
            issuerCertificate = toCertificateHolder(issuer);
            return this;
        }

        public CustomCodeSigningObject build() throws Exception {
            return new CustomCodeSigningObject(cmk, dataBlob, issuerCertificate);
        }
    }

    private static class TBSCustomCodeSigningObject {

        private final DERBitString dataBlob;
        private final X500Name issuerCertificateSubject;

        public static TBSCustomCodeSigningObject getInstance(final ASN1Sequence sequence) {
            if (sequence.size() != 2) {
                throw new IllegalArgumentException("Unexpected object length (" + sequence.size() + ")");
            }

            DERBitString dataBlob = DERBitString.getInstance(sequence.getObjectAt(0));
            X500Name issuerCertificateSubject = X500Name.getInstance(sequence.getObjectAt(1));

            return new TBSCustomCodeSigningObject(dataBlob, issuerCertificateSubject);
        }

        public TBSCustomCodeSigningObject(final byte[] dataBlob, final X509CertificateHolder issuerCertificate) {
            try {
                this.dataBlob = new DERBitString(dataBlob);
                this.issuerCertificateSubject = issuerCertificate.getSubject();
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }

        private TBSCustomCodeSigningObject(final DERBitString dataBlob, final X500Name issuerCertificateSubject) {
            this.dataBlob = dataBlob;
            this.issuerCertificateSubject = issuerCertificateSubject;
        }

        public ASN1Sequence getASN1Structure() {
            return makeSequence(dataBlob, issuerCertificateSubject);
        }

        public byte[] getEncoded() throws Exception {
            return getASN1Structure().getEncoded();
        }
    }
}
