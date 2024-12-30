package ruby.commonsecurity

import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.context.annotation.ComponentScan
import org.springframework.context.annotation.Configuration

@Configuration
@ComponentScan(basePackages = ["ruby.commonsecurity"])
@EnableAutoConfiguration
class AuthLibraryConfig
