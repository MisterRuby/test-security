package ruby.commonsecurity.domain

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.HttpServletResponse
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@Configuration
class SecurityConfig(
    private val objectMapper: ObjectMapper
) {

    @Bean
    fun passwordEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }

    @Bean
    fun authenticationManager(authConfig: AuthenticationConfiguration): AuthenticationManager {
        return authConfig.authenticationManager
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain::class) // 빈이 없을 때만 등록
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.csrf { it.disable() }
            .authorizeHttpRequests { auth ->
                auth.requestMatchers("/login").permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin { it.disable() } // 기본 로그인 폼 비활성화
            .httpBasic { it.disable() } // 기본 브라우저 인증 비활성화
            .logout { logout -> logout.permitAll() }

        return http.build()
    }

    // 로그인 성공 핸들러
    @Bean
    @ConditionalOnMissingBean(AuthenticationSuccessHandler::class) // 빈이 없을 때만 등록
    fun loginSuccessHandler(): AuthenticationSuccessHandler {
        return AuthenticationSuccessHandler { _, response, authentication ->
            val userDetails = authentication.principal as org.springframework.security.core.userdetails.User
            // {message: "Login successful", username : userDetails.username}
            val responseData = mapOf("message" to "Login successful", "username" to userDetails.username)
            response.contentType = "application/json"
            response.writer.write(objectMapper.writeValueAsString(responseData))
        }
    }

    // 로그인 실패 핸들러
    @Bean
    @ConditionalOnMissingBean(AuthenticationFailureHandler::class) // 빈이 없을 때만 등록
    fun loginFailureHandler(): AuthenticationFailureHandler {
        return AuthenticationFailureHandler { _, response, exception ->
            val responseData = mapOf("message" to "Login failed", "error" to exception.message)
            response.contentType = "application/json"
            response.status = HttpServletResponse.SC_UNAUTHORIZED
            response.writer.write(objectMapper.writeValueAsString(responseData))
        }
    }
}

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

@RestController
class LoginController(
    private val authenticationManager: AuthenticationManager,
    private val successHandler: AuthenticationSuccessHandler,
    private val failureHandler: AuthenticationFailureHandler
) {

    @PostMapping("/login")
    fun login(
        @RequestBody request: LoginRequest,
        response: HttpServletResponse
    ) {
        try {
            val authRequest = UsernamePasswordAuthenticationToken(request.email, request.password)
            val authentication: Authentication = authenticationManager.authenticate(authRequest)
            successHandler.onAuthenticationSuccess(null, response, authentication)
        } catch (e: AuthenticationException) {
            failureHandler.onAuthenticationFailure(null, response, e)
        }
    }
}

data class LoginRequest(
    val email: String,
    val password: String
)
