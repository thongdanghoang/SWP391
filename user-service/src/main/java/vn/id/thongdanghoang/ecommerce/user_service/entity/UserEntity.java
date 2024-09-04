package vn.id.thongdanghoang.ecommerce.user_service.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.Fetch;
import org.hibernate.annotations.FetchMode;

import java.util.HashSet;
import java.util.Set;

@NamedEntityGraph(
        name = UserEntity.USER_AUTHORITIES_ENTITY_GRAPH,
        attributeNodes = {
                @NamedAttributeNode("authorities")
        }
)
@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "users")
public class UserEntity extends AbstractAuditableEntity {

    public static final String USER_AUTHORITIES_ENTITY_GRAPH = "user-authorities-entity-graph";

    @ManyToMany(fetch = FetchType.LAZY)
    @Fetch(FetchMode.SUBSELECT)
    @JoinTable(
            name = "users_authorities",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "authority_id")
    )
    private Set<AuthorityEntity> authorities = new HashSet<>();

    @Column(name = "username", nullable = false, unique = true)
    private String username;

    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "email", nullable = false, unique = true)
    private String email;

//    @Column(name = "first_name")
//    private String firstName;
//
//    @Column(name = "last_name")
//    private String lastName;

    @Column(name = "enabled")
    private boolean enabled;

//    @Column(name = "account_non_expired")
//    private boolean accountNonExpired;
//
//    @Column(name = "account_non_locked")
//    private boolean accountNonLocked;
//
//    @Column(name = "credentials_non_expired")
//    private boolean credentialsNonExpired;

    public static UserEntity register(String username, String password, String email) {
        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setPassword(password);
        user.setEmail(email);
        user.setEnabled(true);
        return user;
    }
}
