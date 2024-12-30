package ruby.testsecurity

import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Configuration

@Configuration
@ComponentScan(basePackages = ["ruby.testsecurity"])
@EnableAutoConfiguration
class AuthLibraryConfig