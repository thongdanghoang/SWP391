package vn.id.thongdanghoang.ecommerce.user_service.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "authorities")
public class AuthorityEntity extends AbstractAuditableEntity {

    @Column(name = "name", nullable = false, unique = true)
    private String authority;
}
