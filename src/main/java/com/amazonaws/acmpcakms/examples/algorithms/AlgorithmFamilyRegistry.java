package com.amazonaws.acmpcakms.examples.algorithms;

import com.amazonaws.acmpcakms.examples.algorithms.ecc.*;
import com.amazonaws.acmpcakms.examples.algorithms.mldsa.*;
import com.amazonaws.acmpcakms.examples.algorithms.rsa.*;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public final class AlgorithmFamilyRegistry {

  // Using Map.of() for immutability and better performance
  private static final Map<String, AlgorithmFamily> FAMILIES =
      Map.of(
          "RSA2048", new RSA2048Family(),
          "RSA3072", new RSA3072Family(),
          "RSA4096", new RSA4096Family(),
          "ECP256", new ECP256Family(),
          "ECP384", new ECP384Family(),
          "ECP521", new ECP521Family(),
          "MLDSA44", new MLDSA44Family(),
          "MLDSA65", new MLDSA65Family(),
          "MLDSA87", new MLDSA87Family());

  // Private constructor to prevent instantiation
  private AlgorithmFamilyRegistry() {
    throw new UnsupportedOperationException("Utility class cannot be instantiated");
  }

  public static AlgorithmFamily getFamily(String familyName) {
    if (familyName == null) {
      throw new IllegalArgumentException(
          "Algorithm family name cannot be null. "
              + "Supported families: "
              + getSupportedFamilies());
    }

    AlgorithmFamily family = FAMILIES.get(familyName);
    if (family == null) {
      throw new IllegalArgumentException(
          "Unsupported algorithm family: '"
              + familyName
              + "'. "
              + "Supported families: "
              + getSupportedFamilies());
    }
    return family;
  }

  public static Set<String> getSupportedFamilies() {
    return FAMILIES.keySet();
  }

  public static Map<String, AlgorithmFamily> getFamiliesByType(String keyFactoryAlgorithm) {
    if (keyFactoryAlgorithm == null) {
      throw new IllegalArgumentException("Key factory algorithm cannot be null");
    }

    return FAMILIES.entrySet().stream()
        .filter(entry -> keyFactoryAlgorithm.equals(entry.getValue().getKeyFactoryAlgorithm()))
        .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));
  }

  public static boolean isSupported(String familyName) {
    return familyName != null && FAMILIES.containsKey(familyName);
  }
}
