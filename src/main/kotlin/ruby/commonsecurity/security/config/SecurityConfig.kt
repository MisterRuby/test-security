package ruby.commonsecurity.security.config

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletResponse
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import ruby.commonsecurity.security.jwt.JwtAuthenticationFilter
import ruby.commonsecurity.security.jwt.JwtProperties
import ruby.commonsecurity.security.jwt.JwtUtils

@Configuration
class SecurityConfig(
    private val objectMapper: ObjectMapper,
    private val jwtAuthenticationFilter: JwtAuthenticationFilter,
    private val jwtUtils: JwtUtils,
    private val corsConfig: CorsConfig,
    private val jwtProperties: JwtProperties
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
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http.csrf { it.disable() }
            .cors { it.configurationSource(corsConfig.corsConfigurationSource()) }
            .authorizeHttpRequests { auth ->
                auth.requestMatchers(HttpMethod.POST, "/login", "/refresh-token").permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin { it.disable() } // 기본 로그인 폼 비활성화
            .httpBasic { it.disable() } // 기본 브라우저 인증 비활성화
            .logout { logout -> logout.permitAll() }
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter::class.java)

        return http.build()
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
                "email" to userDetails.username,
                "accessToken" to jwtUtils.generateAccessToken(authentication.name),
                "accessTokenMaxAge" to jwtProperties.accessTokenExpirationMs
            )

            // 리프레시 토큰을 HttpOnly 쿠키로 설정
            val refreshToken = jwtUtils.generateRefreshToken(authentication.name)
            val refreshTokenCookie = Cookie("refreshToken", refreshToken).apply {
                isHttpOnly = true
                secure = true           // HTTPS 환경에서만 전송
                path = "/refresh-token" // 리프레시 토큰 전송 경로 제한
                maxAge = jwtProperties.refreshTokenExpirationMs
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

