package com.datamasking.repository;

import com.datamasking.model.MaskedData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MaskedDataRepository extends JpaRepository<MaskedData, Long> {
    // Custom queries can be added here if needed
}

