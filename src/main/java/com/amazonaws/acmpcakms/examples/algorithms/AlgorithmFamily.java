package com.amazonaws.acmpcakms.examples.algorithms;

import software.amazon.awssdk.services.acmpca.model.KeyAlgorithm;
import software.amazon.awssdk.services.acmpca.model.SigningAlgorithm;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

public interface AlgorithmFamily {

  KeySpec getKmsKeySpec();

  SigningAlgorithmSpec getKmsSigningAlgorithm();

  KeyAlgorithm getPcaKeyAlgorithm();

  SigningAlgorithm getPcaSigningAlgorithm();

  String getBouncyCastleAlgorithmName();

  String getFamilyName();

  String getKeyFactoryAlgorithm();
}
