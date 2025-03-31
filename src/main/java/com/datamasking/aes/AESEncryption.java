package com.datamasking.aes;

import java.util.Arrays;
import java.util.Base64;

/**
 * Custom AES implementation without using any built-in encryption libraries
 */
public class AESEncryption {
    // AES parameters
    private static final int BLOCK_SIZE = 16; // 128 bits
    private static final int KEY_LENGTH = 32; // 256 bits
    private static final int ROUNDS = 14; // For AES-256

    // AES S-box
    private static final byte[] SBOX = {
        (byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5,
        (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76,
        (byte)0xca, (byte)0x82, (byte)0xc9, (byte)0x7d, (byte)0xfa, (byte)0x59, (byte)0x47, (byte)0xf0,
        (byte)0xad, (byte)0xd4, (byte)0xa2, (byte)0xaf, (byte)0x9c, (byte)0xa4, (byte)0x72, (byte)0xc0,
        (byte)0xb7, (byte)0xfd, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3f, (byte)0xf7, (byte)0xcc,
        (byte)0x34, (byte)0xa5, (byte)0xe5, (byte)0xf1, (byte)0x71, (byte)0xd8, (byte)0x31, (byte)0x15,
        (byte)0x04, (byte)0xc7, (byte)0x23, (byte)0xc3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9a,
        (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xe2, (byte)0xeb, (byte)0x27, (byte)0xb2, (byte)0x75,
        (byte)0x09, (byte)0x83, (byte)0x2c, (byte)0x1a, (byte)0x1b, (byte)0x6e, (byte)0x5a, (byte)0xa0,
        (byte)0x52, (byte)0x3b, (byte)0xd6, (byte)0xb3, (byte)0x29, (byte)0xe3, (byte)0x2f, (byte)0x84,
        (byte)0x53, (byte)0xd1, (byte)0x00, (byte)0xed, (byte)0x20, (byte)0xfc, (byte)0xb1, (byte)0x5b,
        (byte)0x6a, (byte)0xcb, (byte)0xbe, (byte)0x39, (byte)0x4a, (byte)0x4c, (byte)0x58, (byte)0xcf,
        (byte)0xd0, (byte)0xef, (byte)0xaa, (byte)0xfb, (byte)0x43, (byte)0x4d, (byte)0x33, (byte)0x85,
        (byte)0x45, (byte)0xf9, (byte)0x02, (byte)0x7f, (byte)0x50, (byte)0x3c, (byte)0x9f, (byte)0xa8,
        (byte)0x51, (byte)0xa3, (byte)0x40, (byte)0x8f, (byte)0x92, (byte)0x9d, (byte)0x38, (byte)0xf5,
        (byte)0xbc, (byte)0xb6, (byte)0xda, (byte)0x21, (byte)0x10, (byte)0xff, (byte)0xf3, (byte)0xd2,
        (byte)0xcd, (byte)0x0c, (byte)0x13, (byte)0xec, (byte)0x5f, (byte)0x97, (byte)0x44, (byte)0x17,
        (byte)0xc4, (byte)0xa7, (byte)0x7e, (byte)0x3d, (byte)0x64, (byte)0x5d, (byte)0x19, (byte)0x73,
        (byte)0x60, (byte)0x81, (byte)0x4f, (byte)0xdc, (byte)0x22, (byte)0x2a, (byte)0x90, (byte)0x88,
        (byte)0x46, (byte)0xee, (byte)0xb8, (byte)0x14, (byte)0xde, (byte)0x5e, (byte)0x0b, (byte)0xdb,
        (byte)0xe0, (byte)0x32, (byte)0x3a, (byte)0x0a, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5c,
        (byte)0xc2, (byte)0xd3, (byte)0xac, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xe4, (byte)0x79,
        (byte)0xe7, (byte)0xc8, (byte)0x37, (byte)0x6d, (byte)0x8d, (byte)0xd5, (byte)0x4e, (byte)0xa9,
        (byte)0x6c, (byte)0x56, (byte)0xf4, (byte)0xea, (byte)0x65, (byte)0x7a, (byte)0xae, (byte)0x08,
        (byte)0xba, (byte)0x78, (byte)0x25, (byte)0x2e, (byte)0x1c, (byte)0xa6, (byte)0xb4, (byte)0xc6,
        (byte)0xe8, (byte)0xdd, (byte)0x74, (byte)0x1f, (byte)0x4b, (byte)0xbd, (byte)0x8b, (byte)0x8a,
        (byte)0x70, (byte)0x3e, (byte)0xb5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xf6, (byte)0x0e,
        (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xb9, (byte)0x86, (byte)0xc1, (byte)0x1d, (byte)0x9e,
        (byte)0xe1, (byte)0xf8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xd9, (byte)0x8e, (byte)0x94,
        (byte)0x9b, (byte)0x1e, (byte)0x87, (byte)0xe9, (byte)0xce, (byte)0x55, (byte)0x28, (byte)0xdf,
        (byte)0x8c, (byte)0xa1, (byte)0x89, (byte)0x0d, (byte)0xbf, (byte)0xe6, (byte)0x42, (byte)0x68,
        (byte)0x41, (byte)0x99, (byte)0x2d, (byte)0x0f, (byte)0xb0, (byte)0x54, (byte)0xbb, (byte)0x16
    };

    // AES inverse S-box
    private static final byte[] INV_SBOX = {
        (byte)0x52, (byte)0x09, (byte)0x6a, (byte)0xd5, (byte)0x30, (byte)0x36, (byte)0xa5, (byte)0x38,
        (byte)0xbf, (byte)0x40, (byte)0xa3, (byte)0x9e, (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb,
        (byte)0x7c, (byte)0xe3, (byte)0x39, (byte)0x82, (byte)0x9b, (byte)0x2f, (byte)0xff, (byte)0x87,
        (byte)0x34, (byte)0x8e, (byte)0x43, (byte)0x44, (byte)0xc4, (byte)0xde, (byte)0xe9, (byte)0xcb,
        (byte)0x54, (byte)0x7b, (byte)0x94, (byte)0x32, (byte)0xa6, (byte)0xc2, (byte)0x23, (byte)0x3d,
        (byte)0xee, (byte)0x4c, (byte)0x95, (byte)0x0b, (byte)0x42, (byte)0xfa, (byte)0xc3, (byte)0x4e,
        (byte)0x08, (byte)0x2e, (byte)0xa1, (byte)0x66, (byte)0x28, (byte)0xd9, (byte)0x24, (byte)0xb2,
        (byte)0x76, (byte)0x5b, (byte)0xa2, (byte)0x49, (byte)0x6d, (byte)0x8b, (byte)0xd1, (byte)0x25,
        (byte)0x72, (byte)0xf8, (byte)0xf6, (byte)0x64, (byte)0x86, (byte)0x68, (byte)0x98, (byte)0x16,
        (byte)0xd4, (byte)0xa4, (byte)0x5c, (byte)0xcc, (byte)0x5d, (byte)0x65, (byte)0xb6, (byte)0x92,
        (byte)0x6c, (byte)0x70, (byte)0x48, (byte)0x50, (byte)0xfd, (byte)0xed, (byte)0xb9, (byte)0xda,
        (byte)0x5e, (byte)0x15, (byte)0x46, (byte)0x57, (byte)0xa7, (byte)0x8d, (byte)0x9d, (byte)0x84,
        (byte)0x90, (byte)0xd8, (byte)0xab, (byte)0x00, (byte)0x8c, (byte)0xbc, (byte)0xd3, (byte)0x0a,
        (byte)0xf7, (byte)0xe4, (byte)0x58, (byte)0x05, (byte)0xb8, (byte)0xb3, (byte)0x45, (byte)0x06,
        (byte)0xd0, (byte)0x2c, (byte)0x1e, (byte)0x8f, (byte)0xca, (byte)0x3f, (byte)0x0f, (byte)0x02,
        (byte)0xc1, (byte)0xaf, (byte)0xbd, (byte)0x03, (byte)0x01, (byte)0x13, (byte)0x8a, (byte)0x6b,
        (byte)0x3a, (byte)0x91, (byte)0x11, (byte)0x41, (byte)0x4f, (byte)0x67, (byte)0xdc, (byte)0xea,
        (byte)0x97, (byte)0xf2, (byte)0xcf, (byte)0xce, (byte)0xf0, (byte)0xb4, (byte)0xe6, (byte)0x73,
        (byte)0x96, (byte)0xac, (byte)0x74, (byte)0x22, (byte)0xe7, (byte)0xad, (byte)0x35, (byte)0x85,
        (byte)0xe2, (byte)0xf9, (byte)0x37, (byte)0xe8, (byte)0x1c, (byte)0x75, (byte)0xdf, (byte)0x6e,
        (byte)0x47, (byte)0xf1, (byte)0x1a, (byte)0x71, (byte)0x1d, (byte)0x29, (byte)0xc5, (byte)0x89,
        (byte)0x6f, (byte)0xb7, (byte)0x62, (byte)0x0e, (byte)0xaa, (byte)0x18, (byte)0xbe, (byte)0x1b,
        (byte)0xfc, (byte)0x56, (byte)0x3e, (byte)0x4b, (byte)0xc6, (byte)0xd2, (byte)0x79, (byte)0x20,
        (byte)0x9a, (byte)0xdb, (byte)0xc0, (byte)0xfe, (byte)0x78, (byte)0xcd, (byte)0x5a, (byte)0xf4,
        (byte)0x1f, (byte)0xdd, (byte)0xa8, (byte)0x33, (byte)0x88, (byte)0x07, (byte)0xc7, (byte)0x31,
        (byte)0xb1, (byte)0x12, (byte)0x10, (byte)0x59, (byte)0x27, (byte)0x80, (byte)0xec, (byte)0x5f,
        (byte)0x60, (byte)0x51, (byte)0x7f, (byte)0xa9, (byte)0x19, (byte)0xb5, (byte)0x4a, (byte)0x0d,
        (byte)0x2d, (byte)0xe5, (byte)0x7a, (byte)0x9f, (byte)0x93, (byte)0xc9, (byte)0x9c, (byte)0xef,
        (byte)0xa0, (byte)0xe0, (byte)0x3b, (byte)0x4d, (byte)0xae, (byte)0x2a, (byte)0xf5, (byte)0xb0,
        (byte)0xc8, (byte)0xeb, (byte)0xbb, (byte)0x3c, (byte)0x83, (byte)0x53, (byte)0x99, (byte)0x61,
        (byte)0x17, (byte)0x2b, (byte)0x04, (byte)0x7e, (byte)0xba, (byte)0x77, (byte)0xd6, (byte)0x26,
        (byte)0xe1, (byte)0x69, (byte)0x14, (byte)0x63, (byte)0x55, (byte)0x21, (byte)0x0c, (byte)0x7d
    };

    // Rcon used in key expansion
    private static final int[] RCON = {
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000,
        0x40000000, 0x80000000, 0x1b000000, 0x36000000
    };

    // Key expansion
    private int[][] expandKey(byte[] key) {
        int Nk = key.length / 4; // Number of 32-bit words in the key
        int[][] w = new int[ROUNDS + 1][4]; // Expanded key

        // Copy the original key to the first Nk words
        for (int i = 0; i < Nk; i++) {
            w[i / 4][i % 4] = ((key[4 * i] & 0xff) << 24) | ((key[4 * i + 1] & 0xff) << 16) |
                              ((key[4 * i + 2] & 0xff) << 8) | (key[4 * i + 3] & 0xff);
        }

        // Expand the key
        for (int i = Nk; i < 4 * (ROUNDS + 1); i++) {
            int temp = w[(i - 1) / 4][(i - 1) % 4];
            if (i % Nk == 0) {
                // RotWord and SubWord
                temp = subWord(rotWord(temp)) ^ RCON[i / Nk - 1];
            } else if (Nk > 6 && i % Nk == 4) {
                // Additional SubWord for AES-256
                temp = subWord(temp);
            }
            w[i / 4][i % 4] = w[(i - Nk) / 4][(i - Nk) % 4] ^ temp;
        }

        return w;
    }

    // Rotate word (for key expansion)
    private int rotWord(int word) {
        return ((word << 8) | ((word >> 24) & 0xff));
    }

    // Substitute word (for key expansion)
    private int subWord(int word) {
        return (SBOX[(word >> 24) & 0xff] & 0xff) << 24 |
               (SBOX[(word >> 16) & 0xff] & 0xff) << 16 |
               (SBOX[(word >> 8) & 0xff] & 0xff) << 8 |
               (SBOX[word & 0xff] & 0xff);
    }

    // Add round key to state
    private byte[][] addRoundKey(byte[][] state, int[][] roundKey, int round) {
        byte[][] result = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                result[i][j] = (byte)(state[i][j] ^ ((roundKey[round][j] >> (24 - 8 * i)) & 0xff));
            }
        }
        return result;
    }

    // SubBytes transformation
    private byte[][] subBytes(byte[][] state) {
        byte[][] result = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                result[i][j] = SBOX[state[i][j] & 0xff];
            }
        }
        return result;
    }

    // InvSubBytes transformation
    private byte[][] invSubBytes(byte[][] state) {
        byte[][] result = new byte[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                result[i][j] = INV_SBOX[state[i][j] & 0xff];
            }
        }
        return result;
    }

    // ShiftRows transformation
    private byte[][] shiftRows(byte[][] state) {
        byte[][] result = new byte[4][4];
        
        // Row 0: no shift
        result[0][0] = state[0][0];
        result[0][1] = state[0][1];
        result[0][2] = state[0][2];
        result[0][3] = state[0][3];
        
        // Row 1: shift left by 1
        result[1][0] = state[1][1];
        result[1][1] = state[1][2];
        result[1][2] = state[1][3];
        result[1][3] = state[1][0];
        
        // Row 2: shift left by 2
        result[2][0] = state[2][2];
        result[2][1] = state[2][3];
        result[2][2] = state[2][0];
        result[2][3] = state[2][1];
        
        // Row 3: shift left by 3
        result[3][0] = state[3][3];
        result[3][1] = state[3][0];
        result[3][2] = state[3][1];
        result[3][3] = state[3][2];
        
        return result;
    }

    // InvShiftRows transformation
    private byte[][] invShiftRows(byte[][] state) {
        byte[][] result = new byte[4][4];
        
        // Row 0: no shift
        result[0][0] = state[0][0];
        result[0][1] = state[0][1];
        result[0][2] = state[0][2];
        result[0][3] = state[0][3];
        
        // Row 1: shift right by 1
        result[1][0] = state[1][3];
        result[1][1] = state[1][0];
        result[1][2] = state[1][1];
        result[1][3] = state[1][2];
        
        // Row 2: shift right by 2
        result[2][0] = state[2][2];
        result[2][1] = state[2][3];
        result[2][2] = state[2][0];
        result[2][3] = state[2][1];
        
        // Row 3: shift right by 3
        result[3][0] = state[3][1];
        result[3][1] = state[3][2];
        result[3][2] = state[3][3];
        result[3][3] = state[3][0];
        
        return result;
    }

    // Galois Field multiplication for MixColumns
    private byte gmul(byte a, byte b) {
        byte p = 0;
        byte counter;
        byte hi_bit_set;
        
        for (counter = 0; counter < 8; counter++) {
            if ((b & 1) != 0) {
                p ^= a;
            }
            
            hi_bit_set = (byte)(a & 0x80);
            a <<= 1;
            
            if (hi_bit_set != 0) {
                a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
            }
            
            b >>= 1;
        }
        
        return p;
    }

    // MixColumns transformation
    private byte[][] mixColumns(byte[][] state) {
        byte[][] result = new byte[4][4];
        
        for (int j = 0; j < 4; j++) {
            result[0][j] = (byte)(gmul((byte)0x02, state[0][j]) ^ gmul((byte)0x03, state[1][j]) ^ 
                                  state[2][j] ^ state[3][j]);
            
            result[1][j] = (byte)(state[0][j] ^ gmul((byte)0x02, state[1][j]) ^ 
                                  gmul((byte)0x03, state[2][j]) ^ state[3][j]);
            
            result[2][j] = (byte)(state[0][j] ^ state[1][j] ^ 
                                  gmul((byte)0x02, state[2][j]) ^ gmul((byte)0x03, state[3][j]));
            
            result[3][j] = (byte)(gmul((byte)0x03, state[0][j]) ^ state[1][j] ^ 
                                  state[2][j] ^ gmul((byte)0x02, state[3][j]));
        }
        
        return result;
    }

    // InvMixColumns transformation
    private byte[][] invMixColumns(byte[][] state) {
        byte[][] result = new byte[4][4];
        
        for (int j = 0; j < 4; j++) {
            result[0][j] = (byte)(gmul((byte)0x0e, state[0][j]) ^ gmul((byte)0x0b, state[1][j]) ^ 
                                  gmul((byte)0x0d, state[2][j]) ^ gmul((byte)0x09, state[3][j]));
            
            result[1][j] = (byte)(gmul((byte)0x09, state[0][j]) ^ gmul((byte)0x0e, state[1][j]) ^ 
                                  gmul((byte)0x0b, state[2][j]) ^ gmul((byte)0x0d, state[3][j]));
            
            result[2][j] = (byte)(gmul((byte)0x0d, state[0][j]) ^ gmul((byte)0x09, state[1][j]) ^ 
                                  gmul((byte)0x0e, state[2][j]) ^ gmul((byte)0x0b, state[3][j]));
            
            result[3][j] = (byte)(gmul((byte)0x0b, state[0][j]) ^ gmul((byte)0x0d, state[1][j]) ^ 
                                  gmul((byte)0x09, state[2][j]) ^ gmul((byte)0x0e, state[3][j]));
        }
        
        return result;
    }

    // Convert byte array to state matrix
    private byte[][] toState(byte[] block) {
        byte[][] state = new byte[4][4];
        for (int i = 0; i < 16; i++) {
            state[i % 4][i / 4] = block[i];
        }
        return state;
    }

    // Convert state matrix to byte array
    private byte[] fromState(byte[][] state) {
        byte[] block = new byte[16];
        for (int i = 0; i < 16; i++) {
            block[i] = state[i % 4][i / 4];
        }
        return block;
    }

    // Encrypt a single block
    private byte[] encryptBlock(byte[] block, int[][] expandedKey) {
        byte[][] state = toState(block);
        
        // Initial round
        state = addRoundKey(state, expandedKey, 0);
        
        // Main rounds
        for (int round = 1; round < ROUNDS; round++) {
            state = subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = addRoundKey(state, expandedKey, round);
        }
        
        // Final round (no MixColumns)
        state = subBytes(state);
        state = shiftRows(state);
        state = addRoundKey(state, expandedKey, ROUNDS);
        
        return fromState(state);
    }

    // Decrypt a single block
    private byte[] decryptBlock(byte[] block, int[][] expandedKey) {
        byte[][] state = toState(block);
        
        // Initial round
        state = addRoundKey(state, expandedKey, ROUNDS);
        
        // Main rounds
        for (int round = ROUNDS - 1; round > 0; round--) {
            state = invShiftRows(state);
            state = invSubBytes(state);
            state = addRoundKey(state, expandedKey, round);
            state = invMixColumns(state);
        }
        
        // Final round (no InvMixColumns)
        state = invShiftRows(state);
        state = invSubBytes(state);
        state = addRoundKey(state, expandedKey, 0);
        
        return fromState(state);
    }

    // Create a 256-bit key from a string
    private byte[] createKey(String keyString) {
        byte[] key = new byte[KEY_LENGTH];
        byte[] keyBytes = keyString.getBytes();
        
        // Use SHA-256 like algorithm to create a 256-bit key
        // This is a simplified version for demonstration
        for (int i = 0; i < KEY_LENGTH; i++) {
            key[i] = (byte)(keyBytes[i % keyBytes.length] ^ (i * 13));
        }
        
        return key;
    }

    // Generate a random IV
    private byte[] generateIV() {
        byte[] iv = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            iv[i] = (byte)(Math.random() * 256);
        }
        return iv;
    }

    // Apply PKCS#7 padding
    private byte[] applyPadding(byte[] data) {
        int paddingLength = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] paddedData = new byte[data.length + paddingLength];
        
        System.arraycopy(data, 0, paddedData, 0, data.length);
        
        // Fill padding bytes with the padding length value
        for (int i = data.length; i < paddedData.length; i++) {
            paddedData[i] = (byte)paddingLength;
        }
        
        return paddedData;
    }

    // Remove PKCS#7 padding
    private byte[] removePadding(byte[] paddedData) {
        int paddingLength = paddedData[paddedData.length - 1] & 0xff;
        
        // Validate padding
        if (paddingLength > BLOCK_SIZE || paddingLength <= 0) {
            throw new IllegalArgumentException("Invalid padding");
        }
        
        for (int i = paddedData.length - paddingLength; i < paddedData.length; i++) {
            if ((paddedData[i] & 0xff) != paddingLength) {
                throw new IllegalArgumentException("Invalid padding");
            }
        }
        
        byte[] data = new byte[paddedData.length - paddingLength];
        System.arraycopy(paddedData, 0, data, 0, data.length);
        
        return data;
    }

    // Encrypt data using AES in CBC mode
    public String encrypt(String plaintext, String key) {
        try {
            byte[] plaintextBytes = plaintext.getBytes("UTF-8");
            byte[] keyBytes = createKey(key);
            byte[] iv = generateIV();
            
            // Pad the plaintext
            byte[] paddedPlaintext = applyPadding(plaintextBytes);
            
            // Expand the key
            int[][] expandedKey = expandKey(keyBytes);
            
            // Encrypt each block in CBC mode
            byte[] ciphertext = new byte[paddedPlaintext.length];
            byte[] previousBlock = iv;
            
            for (int i = 0; i < paddedPlaintext.length; i += BLOCK_SIZE) {
                byte[] block = new byte[BLOCK_SIZE];
                System.arraycopy(paddedPlaintext, i, block, 0, BLOCK_SIZE);
                
                // XOR with previous ciphertext block (or IV for first block)
                for (int j = 0; j < BLOCK_SIZE; j++) {
                    block[j] ^= previousBlock[j];
                }
                
                // Encrypt the block
                byte[] encryptedBlock = encryptBlock(block, expandedKey);
                
                // Copy to ciphertext
                System.arraycopy(encryptedBlock, 0, ciphertext, i, BLOCK_SIZE);
                
                // Update previous block
                previousBlock = encryptedBlock;
            }
            
            // Combine IV and ciphertext
            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            
            // Encode as Base64
            return Base64.getEncoder().encodeToString(combined);
            
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Decrypt data using AES in CBC mode
    public String decrypt(String ciphertext, String key) {
        try {
            byte[] combined = Base64.getDecoder().decode(ciphertext);
            byte[] keyBytes = createKey(key);
            
            // Extract IV and ciphertext
            byte[] iv = new byte[BLOCK_SIZE];
            byte[] encryptedData = new byte[combined.length - BLOCK_SIZE];
            
            System.arraycopy(combined, 0, iv, 0, BLOCK_SIZE);
            System.arraycopy(combined, BLOCK_SIZE, encryptedData, 0, encryptedData.length);
            
            // Expand the key
            int[][] expandedKey = expandKey(keyBytes);
            
            // Decrypt each block in CBC mode
            byte[] paddedPlaintext = new byte[encryptedData.length];
            byte[] previousBlock = iv;
            
            for (int i = 0; i < encryptedData.length; i += BLOCK_SIZE) {
                byte[] block = new byte[BLOCK_SIZE];
                System.arraycopy(encryptedData, i, block, 0, BLOCK_SIZE);
                
                // Decrypt the block
                byte[] decryptedBlock = decryptBlock(block, expandedKey);
                
                // XOR with previous ciphertext block (or IV for first block)
                for (int j = 0; j < BLOCK_SIZE; j++) {
                    decryptedBlock[j] ^= previousBlock[j];
                }
                
                // Copy to plaintext
                System.arraycopy(decryptedBlock, 0, paddedPlaintext, i, BLOCK_SIZE);
                
                // Update previous block
                previousBlock = block;
            }
            
            // Remove padding
            byte[] plaintext = removePadding(paddedPlaintext);
            
            // Convert to string
            return new String(plaintext, "UTF-8");
            
        } catch (Exception e) {
            e.printStackTrace();
            return "Error: Invalid key or corrupted data";
        }
    }
}

