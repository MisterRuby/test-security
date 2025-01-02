package ruby.commonsecurity.security.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.stereotype.Component
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
class CorsConfig(private val corsProperties: CorsProperties) {
    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        return UrlBasedCorsConfigurationSource().also {
            it.registerCorsConfiguration("/jwk/**", resourceServersCorsConfiguration())       // corsProperties.resourceServers 도메인에만 허용
            it.registerCorsConfiguration("/auth/**", clientServersCorsConfiguration())    // corsProperties.allowedOrigins 도메인에만 허용
        }
    }

    private fun resourceServersCorsConfiguration(): CorsConfiguration {
        return CorsConfiguration().also {
            it.allowedOrigins = corsProperties.resourceServers // 허용할 도메인
            it.allowedMethods = listOf("GET") // 허용할 HTTP 메서드
            it.allowedHeaders = listOf("*") // 허용할 헤더
            it.allowCredentials = true // 쿠키를 포함한 자격 증명 허용
        }
    }

    private fun clientServersCorsConfiguration(): CorsConfiguration {
        return CorsConfiguration().also {
            it.allowedOrigins = corsProperties.allowedOrigins // 허용할 도메인
            it.allowedMethods = listOf("GET", "POST") // 허용할 HTTP 메서드
            it.allowedHeaders = listOf("*") // 허용할 헤더
            it.allowCredentials = true // 쿠키를 포함한 자격 증명 허용
        }
    }
}

@Component
@ConfigurationProperties(prefix = "cors")
class CorsProperties {
    var resourceServers: List<String> = emptyList()
    var allowedOrigins: List<String> = emptyList()
}
