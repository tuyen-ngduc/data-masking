package com.datamasking.model;


import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "masked_data")
public class MaskedData {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "original_data_hash", nullable = false)
    private String originalDataHash;

    @Column(name = "masked_data", nullable = false, columnDefinition = "TEXT")
    private String maskedData;

    @Column(name = "key_id", nullable = false)
    private String keyId;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    // Getters and setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getOriginalDataHash() {
        return originalDataHash;
    }

    public void setOriginalDataHash(String originalDataHash) {
        this.originalDataHash = originalDataHash;
    }

    public String getMaskedData() {
        return maskedData;
    }

    public void setMaskedData(String maskedData) {
        this.maskedData = maskedData;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }
}

