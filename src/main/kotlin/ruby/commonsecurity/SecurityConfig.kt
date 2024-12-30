package ruby.commonsecurity

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.CookieValue
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import ruby.commonsecurity.domain.AccountStatus
import ruby.commonsecurity.domain.UserInfoRepository
import ruby.commonsecurity.jwt.JwtAuthenticationFilter
import ruby.commonsecurity.jwt.JwtUtils

@Configuration
class SecurityConfig(
    private val objectMapper: ObjectMapper,
    private val jwtAuthenticationFilter: JwtAuthenticationFilter,
    private val jwtUtils: JwtUtils
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
    fun commonSecurityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) }
            .authorizeHttpRequests { auth ->
                auth.requestMatchers("/login").permitAll()
                    .anyRequest().authenticated()
            }
            .sessionManagement { session ->
                session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS) // 세션 항상 생성
            }
            .formLogin { it.disable() } // 기본 로그인 폼 비활성화
            .httpBasic { it.disable() } // 기본 브라우저 인증 비활성화
            .logout { logout -> logout.permitAll() }
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter::class.java)

        return http.build()
    }

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.allowedOrigins = listOf("http://www.test.com") // 허용할 도메인
        configuration.allowedMethods = listOf("GET", "POST", "PUT", "DELETE") // 허용할 HTTP 메서드
        configuration.allowedHeaders = listOf("*") // 허용할 헤더
        configuration.allowCredentials = true // 쿠키를 포함한 자격 증명 허용

        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration) // 모든 경로에 적용
        return source
    }

    // 로그인 성공 기본 핸들러
    @Bean
    @ConditionalOnMissingBean(AuthenticationSuccessHandler::class) // 빈이 없을 때만 등록
    fun defaultLoginSuccessHandler(): AuthenticationSuccessHandler {
        return AuthenticationSuccessHandler { _, response, authentication ->
            val userDetails = authentication.principal as org.springframework.security.core.userdetails.User

            // {message: "Login successful", username : userDetails.username}
            val responseData = mapOf(
                "message" to "Login successful",
                "username" to userDetails.username,
                "accessToken" to jwtUtils.generateAccessToken(authentication.name),
            )

            // 리프레시 토큰을 HttpOnly 쿠키로 설정
            val refreshToken = jwtUtils.generateRefreshToken(authentication.name)
            val refreshTokenCookie = Cookie("refreshToken", refreshToken).apply {
                isHttpOnly = true
                secure = true // HTTPS 환경에서만 전송
                path = "/refresh-token" // 리프레시 토큰 전송 경로 제한
                maxAge = 7 * 24 * 60 * 60 // 7일
            }
            response.addCookie(refreshTokenCookie)

            response.contentType = "application/json"
            response.writer.write(objectMapper.writeValueAsString(responseData))
        }
    }

    // 로그인 실패 기본 핸들러
    @Bean
    @ConditionalOnMissingBean(AuthenticationFailureHandler::class) // 빈이 없을 때만 등록
    fun defaultLoginFailureHandler(): AuthenticationFailureHandler {
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
    private val failureHandler: AuthenticationFailureHandler,
    private val jwtUtils: JwtUtils
) {

    @PostMapping("/login")
    fun login(
        @RequestBody request: LoginRequest,
        response: HttpServletResponse
    ) {
        try {
            val authToken = UsernamePasswordAuthenticationToken(request.email, request.password)
            val authentication: Authentication = authenticationManager.authenticate(authToken)
            successHandler.onAuthenticationSuccess(null, response, authentication)
        } catch (e: AuthenticationException) {
            failureHandler.onAuthenticationFailure(null, response, e)
        }
    }

    @PostMapping("/refresh-token")
    fun refreshToken(
        @CookieValue("refreshToken") refreshToken: String?, // 쿠키에서 리프레시 토큰 가져옴
        response: HttpServletResponse
    ): ResponseEntity<Map<String, String>> {
        if (refreshToken == null || !jwtUtils.validateRefreshToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                mapOf("error" to "Invalid or expired refresh token")
            )
        }

        // 리프레시 토큰 검증 후 새 액세스 토큰 발급
        val username = jwtUtils.getUsernameFromRefreshToken(refreshToken)
        val accessToken = jwtUtils.generateAccessToken(username)

        return ResponseEntity.ok(mapOf("accessToken" to accessToken))
    }
}

data class LoginRequest(
    val email: String,
    val password: String
)

data class RefreshTokenRequest(
    val refreshToken: String
)
