package vn.id.thongdanghoang.ecommerce.user_service.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import vn.id.thongdanghoang.ecommerce.user_service.entity.AuthorityEntity;
import vn.id.thongdanghoang.ecommerce.user_service.entity.UserEntity;

import java.util.Collection;

public record SecurityUser(UserEntity user) implements UserDetails {

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
    public boolean isEnabled() {
        return user.isEnabled();
    }

    @Override
    public String getPassword() {
        return this.user.getPassword();
    }

    @Override
    public String getUsername() {
        return this.user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }
}
