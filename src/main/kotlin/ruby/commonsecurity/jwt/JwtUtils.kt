package ruby.commonsecurity.jwt

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import ruby.commonsecurity.CustomUserDetailsService
import java.security.Key
import java.util.*

@Component
class JwtUtils {
    private val accessTokenSecret: Key = Keys.secretKeyFor(SignatureAlgorithm.HS256)
    private val refreshTokenSecret: Key = Keys.secretKeyFor(SignatureAlgorithm.HS256)

    private val accessTokenExpirationMs: Long = 15 * 60 * 1000 // 15분
    private val refreshTokenExpirationMs: Long = 7 * 24 * 60 * 60 * 1000 // 7일

    fun generateAccessToken(username: String): String {
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(Date())
            .setExpiration(Date(System.currentTimeMillis() + accessTokenExpirationMs))
            .signWith(accessTokenSecret)
            .compact()
    }

    fun generateRefreshToken(username: String): String {
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(Date())
            .setExpiration(Date(System.currentTimeMillis() + refreshTokenExpirationMs))
            .signWith(refreshTokenSecret)
            .compact()
    }


    fun validateAccessToken(token: String): Boolean {
        return try {
            Jwts.parserBuilder().setSigningKey(accessTokenSecret).build().parseClaimsJws(token)
            true
        } catch (ex: Exception) {
            false
        }
    }

    fun validateRefreshToken(token: String): Boolean {
        return try {
            Jwts.parserBuilder().setSigningKey(refreshTokenSecret).build().parseClaimsJws(token)
            true
        } catch (ex: Exception) {
            false
        }
    }

    fun getUsernameFromToken(token: String): String {
        val claims = Jwts.parserBuilder().setSigningKey(accessTokenSecret).build().parseClaimsJws(token).body
        return claims.subject
    }

    fun getUsernameFromRefreshToken(token: String): String {
        val claims = Jwts.parserBuilder().setSigningKey(refreshTokenSecret).build().parseClaimsJws(token).body
        return claims.subject
    }
}

@Component
class JwtAuthenticationFilter(
    private val jwtUtils: JwtUtils,
    private val userDetailsService: CustomUserDetailsService
) : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val authHeader = request.getHeader("Authorization")
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            val jwt = authHeader.substring(7)
            if (jwtUtils.validateAccessToken(jwt)) {
                val username = jwtUtils.getUsernameFromToken(jwt)
                val userDetails = userDetailsService.loadUserByUsername(username)
                val authToken = UsernamePasswordAuthenticationToken(
                    userDetails, null, userDetails.authorities
                )
                authToken.details = WebAuthenticationDetailsSource().buildDetails(request)
                SecurityContextHolder.getContext().authentication = authToken
            }
        }
        filterChain.doFilter(request, response)
    }
}
