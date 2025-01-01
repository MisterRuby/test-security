package ruby.commonsecurity.security.config

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.stereotype.Component
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Component
@ConfigurationProperties(prefix = "cors")
class CorsProperties {
    var allowedOrigins: List<String> = emptyList()
}

@Configuration
class CorsConfig(private val corsProperties: CorsProperties) {

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration()
        configuration.allowedOrigins = corsProperties.allowedOrigins // 허용할 도메인
        configuration.allowedMethods = listOf("GET", "POST") // 허용할 HTTP 메서드
        configuration.allowedHeaders = listOf("*") // 허용할 헤더
        configuration.allowCredentials = true // 쿠키를 포함한 자격 증명 허용

        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", configuration) // 모든 경로에 적용
        return source
    }
}
