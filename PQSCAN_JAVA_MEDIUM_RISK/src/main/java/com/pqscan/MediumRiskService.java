package com.pqscan;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class MediumRiskService {
    public void trigger() throws Exception {
        // --- PKI (RSA-3072, ECDSA, Ed25519) ---
        KeyPairGenerator rsa3 = KeyPairGenerator.getInstance("RSA");
        rsa3.initialize(3072); // Medium Risk 標準
        
        KeyPairGenerator ecdsa = KeyPairGenerator.getInstance("EC");
        ecdsa.initialize(new ECGenParameterSpec("secp256r1")); // P-256
        ecdsa.initialize(new ECGenParameterSpec("secp384r1")); // P-384
        
        // --- Cipher Suite (AES-128, ChaCha20) ---
        Cipher aes128 = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher chacha = Cipher.getInstance("ChaCha20");

        // --- Hash (SHA-256, 384, 512) ---
        MessageDigest.getInstance("SHA-256").digest();
        MessageDigest.getInstance("SHA-384").digest();
        MessageDigest.getInstance("SHA-512").digest();

        // --- KEX / Curves (x25519, x448, brainpool) ---
        KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
        KeyPairGenerator x25519Gen = KeyPairGenerator.getInstance("X25519");
        KeyPairGenerator x448Gen = KeyPairGenerator.getInstance("X448");
        
        // Brainpool 系列
        ecdsa.initialize(new ECGenParameterSpec("brainpoolP256r1"));
        ecdsa.initialize(new ECGenParameterSpec("brainpoolP384r1"));
        ecdsa.initialize(new ECGenParameterSpec("brainpoolP512r1"));
    }
}
