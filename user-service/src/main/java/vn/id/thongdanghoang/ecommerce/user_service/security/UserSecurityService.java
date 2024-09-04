package vn.id.thongdanghoang.ecommerce.user_service.security;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import vn.id.thongdanghoang.ecommerce.user_service.entity.UserEntity;
import vn.id.thongdanghoang.ecommerce.user_service.repository.UserRepository;

@Service
@Transactional(rollbackOn = Throwable.class)
@RequiredArgsConstructor
public class UserSecurityService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public SecurityUser loadUserByUsername(String username)
            throws UsernameNotFoundException {
        return new SecurityUser(this.userRepository
                .findByUsernameWithAuthorities(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"))
        );
    }

    public void createUser(UserEntity user) {
        var hashed = passwordEncoder.encode(user.getPassword());
    }

    public void updateUser(UserEntity user) {

    }

    public void deleteUser(String username) {

    }

    public void changePassword(String oldPassword, String newPassword) {
        if (passwordEncoder.matches(oldPassword, newPassword)) {
            var hashed = passwordEncoder.encode(newPassword);
        }
    }

    public boolean userExists(String username) {
        return StringUtils.isNoneBlank( username) && userRepository.existsByUsername(username);
    }
}
