package com.rosoa0475.oauthjwt.repository;

import com.rosoa0475.oauthjwt.domain.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
}
