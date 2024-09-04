package vn.id.thongdanghoang.ecommerce.user_service.repository;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import vn.id.thongdanghoang.ecommerce.user_service.entity.UserEntity;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends CrudRepository<UserEntity, UUID> {

    @EntityGraph(UserEntity.USER_AUTHORITIES_ENTITY_GRAPH)
    @Query("SELECT u FROM UserEntity u WHERE u.username = :username")
    Optional<UserEntity> findByUsernameWithAuthorities(String username);

    boolean existsByUsername(String username);
}
