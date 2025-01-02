package ruby.commonsecurity

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.scheduling.annotation.EnableScheduling

/**
 * 엑세스 토큰 / 리프레시 토큰 발급
 * 리프레시 토큰 인증
 * 리소스 서버에 엑세스 토큰 인증을 위한 공개키 발급
 */
@SpringBootApplication
@EnableScheduling
class App

fun main(args: Array<String>) {
    runApplication<App>(*args)
}
