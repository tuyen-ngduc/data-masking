package com.datamasking.service;

import com.datamasking.aes.AESEncryption;
import com.datamasking.model.MaskedData;
import com.datamasking.repository.MaskedDataRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

@Service
public class DataMaskingService {

    @Autowired
    private MaskedDataRepository maskedDataRepository;

    private AESEncryption aesEncryption = new AESEncryption();

    /**
     * Mask data using AES encryption
     */
    public String maskData(String data, String key) {
        if (data == null || key == null || data.isEmpty() || key.isEmpty()) {
            return "";
        }

        return aesEncryption.encrypt(data, key);
    }

    /**
     * Unmask data using AES decryption
     */
    public String unmaskData(String maskedData, String key) {
        if (maskedData == null || key == null || maskedData.isEmpty() || key.isEmpty()) {
            return "";
        }

        return aesEncryption.decrypt(maskedData, key);
    }

    /**
     * Apply partial masking to data (e.g., 123456789012 -> 1234XXXXXX12)
     */
    public String applyPartialMasking(String data, String pattern) {
        if (data == null || data.isEmpty()) {
            return "";
        }

        switch (pattern) {
            case "show-4-hide-middle-show-2":
                if (data.length() <= 6) return data; // Too short to mask meaningfully
                String firstFour = data.substring(0, 4);
                String lastTwo = data.substring(data.length() - 2);
                int middleLength = data.length() - 6;
                StringBuilder maskedMiddle = new StringBuilder();
                for (int i = 0; i < middleLength; i++) {
                    maskedMiddle.append("X");
                }
                return firstFour + maskedMiddle.toString() + lastTwo;

            case "show-first-4":
                if (data.length() <= 4) return data;
                String first4 = data.substring(0, 4);
                StringBuilder restMasked = new StringBuilder();
                for (int i = 0; i < data.length() - 4; i++) {
                    restMasked.append("X");
                }
                return first4 + restMasked.toString();

            case "show-last-4":
                if (data.length() <= 4) return data;
                StringBuilder maskedStart = new StringBuilder();
                for (int i = 0; i < data.length() - 4; i++) {
                    maskedStart.append("X");
                }
                String last4 = data.substring(data.length() - 4);
                return maskedStart.toString() + last4;

            default:
                return data;
        }
    }

    /**
     * Hash the key using SHA-256
     */
    private String hashKey(String key) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = digest.digest(key.getBytes(StandardCharsets.UTF_8));

            // Convert byte array to hexadecimal string
            StringBuilder hexString = new StringBuilder();
            for (byte b : encodedHash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return key; // Fallback to original key if hashing fails
        }
    }

    /**
     * Save masked data to database
     */
    public MaskedData saveMaskedData(String originalData, String maskedData, String keyId) {
        MaskedData data = new MaskedData();
        data.setOriginalDataHash(String.valueOf(originalData.hashCode()));
        data.setMaskedData(maskedData);

        // Hash the key before storing it
        String hashedKey = hashKey(keyId);
        data.setKeyId(hashedKey);

        return maskedDataRepository.save(data);
    }

    /**
     * Get all masked data
     */
    public List<MaskedData> getAllMaskedData() {
        return maskedDataRepository.findAll();
    }

    /**
     * Get masked data by ID
     */
    public MaskedData getMaskedDataById(Long id) {
        return maskedDataRepository.findById(id).orElse(null);
    }

    /**
     * Decrypt data and then apply partial masking
     */
    public String decryptAndPartiallyMask(String encryptedData, String key, String pattern) {
        if (encryptedData == null || key == null || encryptedData.isEmpty() || key.isEmpty()) {
            return "";
        }

        // First decrypt the data
        String decryptedData = unmaskData(encryptedData, key);

        // If decryption failed, return error
        if (decryptedData.startsWith("Error:")) {
            return decryptedData;
        }

        // Then apply partial masking to the decrypted data
        return applyPartialMasking(decryptedData, pattern);
    }
}

