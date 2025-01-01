package ruby.commonsecurity.entity

import jakarta.persistence.*
import java.time.LocalDateTime

@Entity
data class JwtTokenKey(
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,

    @Column(nullable = false, length = 500)
    val publicKey: String,

    @Column(nullable = false)
    val createdDate: LocalDateTime = LocalDateTime.now(),
)
