package com.amazonaws.acmpcakms.examples;

import com.amazonaws.acmpcakms.examples.algorithms.AlgorithmFamily;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.util.Objects;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.SignRequest;
import software.amazon.awssdk.services.kms.model.SignResponse;

public class Signing {

  public static ContentSigner createContentSigner(
      AsymmetricCMK cmk, AlgorithmFamily algorithmFamily) throws Exception {
    return new KMSCMKContentSignerBuilder(cmk, algorithmFamily).build();
  }

  private static AlgorithmIdentifier findAlgorithmIdentifier(AlgorithmFamily algorithmFamily) {
    SignatureAlgorithmIdentifierFinder algorithmIdentifier =
        new DefaultSignatureAlgorithmIdentifierFinder();
    String bouncyCastleAlgorithm = algorithmFamily.getBouncyCastleAlgorithmName();

    try {
      return algorithmIdentifier.find(bouncyCastleAlgorithm);
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "BouncyCastle algorithm "
              + bouncyCastleAlgorithm
              + " from family "
              + algorithmFamily.getFamilyName()
              + " is not supported",
          e);
    }
  }

  private static class KMSCMKContentSignerBuilder {

    private final AsymmetricCMK cmk;
    private final AlgorithmFamily algorithmFamily;

    public KMSCMKContentSignerBuilder(AsymmetricCMK cmk, AlgorithmFamily algorithmFamily) {
      this.cmk = cmk;
      this.algorithmFamily = algorithmFamily;
    }

    public ContentSigner build() {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      AlgorithmIdentifier algorithmIdentifier = findAlgorithmIdentifier(algorithmFamily);

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
          KmsClient client = cmk.getClient();
          String keyId = cmk.getKeyId();
          byte[] input = outputStream.toByteArray();

          SignRequest signRequest =
              SignRequest.builder()
                  .keyId(keyId)
                  .signingAlgorithm(algorithmFamily.getKmsSigningAlgorithm())
                  .message(SdkBytes.fromByteArray(input))
                  .build();

          SignResponse signResponse = client.sign(signRequest);
          byte[] signature = signResponse.signature().asByteArray();

          System.out.println(
              "KMS Signed message with "
                  + algorithmFamily.getFamilyName()
                  + " key="
                  + cmk.getKeyId()
                  + ", msgLen="
                  + input.length
                  + " bytes, signatureLen="
                  + signature.length
                  + " bytes.");

          return signature;
        }
      };
    }
  }

  public static class Signature {
    private final AlgorithmIdentifier algorithmIdentifier;
    private final DERBitString signature;

    public Signature(AlgorithmFamily algorithmFamily, byte[] signature) {
      this.algorithmIdentifier = findAlgorithmIdentifier(algorithmFamily);
      this.signature = new DERBitString(signature);
    }

    public Signature(AlgorithmIdentifier algorithmIdentifier, DERBitString signature) {
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
