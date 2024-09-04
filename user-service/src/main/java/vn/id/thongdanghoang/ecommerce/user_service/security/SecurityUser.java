package vn.id.thongdanghoang.ecommerce.user_service.security;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import vn.id.thongdanghoang.ecommerce.user_service.entity.AuthorityEntity;
import vn.id.thongdanghoang.ecommerce.user_service.entity.UserEntity;

import java.util.Collection;

@RequiredArgsConstructor
public class SecurityUser implements UserDetails {

    private final UserEntity user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getAuthorities()
                .stream()
                .map(this::mapToGrantedAuthority)
                .toList();
    }

    private GrantedAuthority mapToGrantedAuthority(AuthorityEntity authority) {
        return new SimpleGrantedAuthority(authority.getAuthority());
    }

    @Override
    public String getPassword() {
        return this.user.getPassword();
    }

    @Override
    public String getUsername() {
        return this.user.getPassword();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.isEnabled();
    }
}
