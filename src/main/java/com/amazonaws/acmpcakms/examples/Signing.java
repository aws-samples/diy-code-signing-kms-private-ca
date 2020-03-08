package com.amazonaws.acmpcakms.examples;

import com.amazonaws.services.kms.AWSKMS;
import com.amazonaws.services.kms.model.SignRequest;
import com.amazonaws.services.kms.model.SigningAlgorithmSpec;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Objects;

public class Signing {

    public static final String SIGNATURE_ALGORITHM = SigningAlgorithmSpec.RSASSA_PKCS1_V1_5_SHA_256.name();

    public static Signature generateSignature(final AsymmetricCMK cmk, final byte[] encoded) throws Exception {
        ContentSigner contentSigner = new KMSCMKContentSignerBuilder(cmk)
                .build(SIGNATURE_ALGORITHM);

        OutputStream outputStream = contentSigner.getOutputStream();
        outputStream.write(encoded);
        outputStream.close();

        byte[] signature = contentSigner.getSignature();

        return new Signature(SIGNATURE_ALGORITHM, signature);
    }

    public static PKCS10CertificationRequest sign(final AsymmetricCMK cmk, final PKCS10CertificationRequestBuilder csrBuilder) {
        ContentSigner contentSigner = new KMSCMKContentSignerBuilder(cmk)
                .build(SIGNATURE_ALGORITHM);

        return csrBuilder.build(contentSigner);
    }
    private static AlgorithmIdentifier findAlgorithmIdentifier(final String signatureAlgorithm) {
        SignatureAlgorithmIdentifierFinder algorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder();
        switch (signatureAlgorithm) {
            case "RSASSA_PSS_SHA_256":
                return algorithmIdentifier.find("SHA256WITHRSAANDMGF1");
            case "RSASSA_PSS_SHA_384":
                return algorithmIdentifier.find("SHA384WITHRSAANDMGF1");
            case "RSASSA_PSS_SHA_512":
                return algorithmIdentifier.find("SHA512WITHRSAANDMGF1");
            case "RSASSA_PKCS1_V1_5_SHA_256":
                return algorithmIdentifier.find("SHA256WITHRSA");
            case "RSASSA_PKCS1_V1_5_SHA_384":
                return algorithmIdentifier.find("SHA384WITHRSA");
            case "RSASSA_PKCS1_V1_5_SHA_512":
                return algorithmIdentifier.find("SHA512WITHRSA");
            case "ECDSA_SHA_256":
                return algorithmIdentifier.find("SHA256WITHECDSA");
            case "ECDSA_SHA_384":
                return algorithmIdentifier.find("SHA384WITHECDSA");
            case "ECDSA_SHA_512":
                return algorithmIdentifier.find("SHA512WITHECDSA");
            default:
                throw new IllegalArgumentException("SignatureAlgorithm " + signatureAlgorithm + " is not supported");
        }
    }

    private static class KMSCMKContentSignerBuilder {

        private final AsymmetricCMK cmk;

        public KMSCMKContentSignerBuilder(final AsymmetricCMK cmk) {
            this.cmk = cmk;
        }

        public ContentSigner build(final String signatureAlgorithm) {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            AlgorithmIdentifier algorithmIdentifier = findAlgorithmIdentifier(signatureAlgorithm);

            return new ContentSigner() {
                @Override
                public AlgorithmIdentifier getAlgorithmIdentifier() {
                    return algorithmIdentifier;
                }

                @Override
                public OutputStream getOutputStream() {
                    return outputStream;
                }

                @Override
                public byte[] getSignature() {
                    AWSKMS client = cmk.getClient();
                    String keyId = cmk.getKeyId();
                    byte[] input = outputStream.toByteArray();

                    System.out.println("Generating signature with key=" + cmk.getKeyId() + " for input " + Base64.getEncoder().encodeToString(input));

                    ByteBuffer message = ByteBuffer.wrap(input);

                    SignRequest signRequest = new SignRequest()
                            .withKeyId(keyId)
                            .withSigningAlgorithm(signatureAlgorithm)
                            .withMessage(message);

                    byte[] signature = client.sign(signRequest)
                            .getSignature()
                            .array();

                    System.out.println("Signature with key=" + keyId + ": " + Base64.getEncoder().encodeToString(signature));

                    return signature;
                }
            };
        }
    }

    public static class Signature {
        private final AlgorithmIdentifier algorithmIdentifier;
        private final DERBitString signature;

        public Signature(final String signatureAlgorithm, final byte[] signature) {
            this.algorithmIdentifier = findAlgorithmIdentifier(signatureAlgorithm);
            this.signature = new DERBitString(signature);
        }

        public Signature(final AlgorithmIdentifier algorithmIdentifier, final DERBitString signature) {
            if (Objects.isNull(algorithmIdentifier)) {
                throw new IllegalArgumentException("An algorithm identifier must be specified");
            }

            if (Objects.isNull(signature)) {
                throw new IllegalArgumentException("A signature must be specified");
            }

            this.algorithmIdentifier = algorithmIdentifier;
            this.signature = signature;
        }

        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return algorithmIdentifier;
        }

        public DERBitString getSignature() {
            return signature;
        }
    }
}
