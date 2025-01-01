package ruby.commonsecurity.security

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import ruby.commonsecurity.entity.AccountStatus
import ruby.commonsecurity.entity.UserInfoRepository

@Service
class CustomUserDetailsService(
    private val userInfoRepository: UserInfoRepository
) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val user = userInfoRepository.findByEmail(username)
            ?: throw UsernameNotFoundException("User not found with email: $username")

        return User(
            user.email,
            user.password,
//            listOf() // 권한은 필요에 따라 설정
            getAuthorities(user.accountStatus)
        )
    }

    private fun getAuthorities(accountStatus: AccountStatus): List<GrantedAuthority> {
        return listOf(SimpleGrantedAuthority("ROLE_${accountStatus.name}"))
    }
}
