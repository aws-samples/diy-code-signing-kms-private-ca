package com.amazonaws.acmpcakms.examples.algorithms.ecc;

import com.amazonaws.acmpcakms.examples.algorithms.AlgorithmFamily;
import software.amazon.awssdk.services.acmpca.model.KeyAlgorithm;
import software.amazon.awssdk.services.acmpca.model.SigningAlgorithm;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

public class ECP521Family implements AlgorithmFamily {

  @Override
  public KeySpec getKmsKeySpec() {
    return KeySpec.ECC_NIST_P521;
  }

  @Override
  public SigningAlgorithmSpec getKmsSigningAlgorithm() {
    return SigningAlgorithmSpec.ECDSA_SHA_512;
  }

  @Override
  public KeyAlgorithm getPcaKeyAlgorithm() {
    return KeyAlgorithm.EC_SECP521_R1;
  }

  @Override
  public SigningAlgorithm getPcaSigningAlgorithm() {
    return SigningAlgorithm.SHA512_WITHECDSA;
  }

  @Override
  public String getBouncyCastleAlgorithmName() {
    return "SHA512WITHECDSA";
  }

  @Override
  public String getFamilyName() {
    return "ECP521";
  }

  @Override
  public String getKeyFactoryAlgorithm() {
    return "EC";
  }
}
