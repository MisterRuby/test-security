package ruby.commonsecurity.security

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import ruby.commonsecurity.domain.AccountStatus
import ruby.commonsecurity.domain.UserInfoRepository

@Service
class CustomUserDetailsService(
    private val userInfoRepository: UserInfoRepository
) : UserDetailsService {

    override fun loadUserByUsername(username: String): UserDetails {
        val user = userInfoRepository.findByEmail(username)
            ?: throw UsernameNotFoundException("User not found with email: $username")

        return org.springframework.security.core.userdetails.User(
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