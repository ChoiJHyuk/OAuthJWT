package com.rosoa0475.oauthjwt.repository;

import com.rosoa0475.oauthjwt.domain.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByRegistrationId(Long registrationId);
}
