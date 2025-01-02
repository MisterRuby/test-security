package ruby.commonsecurity.security

import jakarta.servlet.http.HttpServletResponse
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.web.bind.annotation.*
import ruby.commonsecurity.security.jwt.Jwk
import ruby.commonsecurity.security.jwt.JwtUtils

@RestController
@RequestMapping("/auth")
class AuthController(
    private val authenticationManager: AuthenticationManager,
    private val successHandler: AuthenticationSuccessHandler,
    private val failureHandler: AuthenticationFailureHandler,
    private val jwtUtils: JwtUtils,
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

    @GetMapping("/refresh-token")
    fun refreshToken(
        @CookieValue("refreshToken") refreshToken: String?, // 쿠키에서 리프레시 토큰 가져옴
        response: HttpServletResponse
    ): ResponseEntity<Map<String, String>> {
        if (refreshToken == null || !jwtUtils.validateToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                mapOf("error" to "Invalid or expired refresh token")
            )
        }

        // 리프레시 토큰 검증 후 새 액세스 토큰 발급
        val username = jwtUtils.getUsernameFromToken(refreshToken)
        val accessToken = jwtUtils.generateToken(username)

        return ResponseEntity.ok(mapOf("accessToken" to accessToken))
    }
}

data class LoginRequest(
    val email: String,
    val password: String
)


@RestController
@RequestMapping("/jwk")
class JwtController(
    private val jwtUtils: JwtUtils
) {
    @GetMapping
    fun getJwk(): Jwk {
        return jwtUtils.getJwk()
    }
}
