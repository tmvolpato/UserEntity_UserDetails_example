package br.com.poc.netflix.ia.authorization.domain.model

import br.com.poc.netflix.ia.authorization.domain.common.constants.CollectionConstant
import br.com.poc.netflix.ia.authorization.domain.common.constants.FieldConstant
import br.com.poc.netflix.ia.authorization.domain.enums.RoleEnum
import org.springframework.data.annotation.Id
import org.springframework.data.mongodb.core.index.Indexed
import org.springframework.data.mongodb.core.mapping.Document
import org.springframework.data.mongodb.core.mapping.Field
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import javax.validation.constraints.Email
import javax.validation.constraints.NotBlank

@Document(collection = CollectionConstant.USER)
class UserEntity internal constructor(

        @Id
        val id: String,

        @field:NotBlank
        @Indexed(unique = true)
        @Field(name = FieldConstant.IDENTIFIER)
        val identifier: String,

        @field:Email
        @field:NotBlank
        @Indexed(unique = true)
        @Field(name = FieldConstant.USERNAME)
        val email: String,

        @field:NotBlank
        @Field(name = FieldConstant.PASSWORD)
        val passwordHash: String,

        @Field(name = FieldConstant.ENABLED)
        val enabled: Boolean = false,

        @Field(name = FieldConstant.ROLES)
        val roles: List<RoleEnum>

) : UserDetails {

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> {
        val authorities = ArrayList<GrantedAuthority>()
        for (roleEnum in this.roles) {
            authorities.add(SimpleGrantedAuthority(roleEnum.name))
        }

        return authorities
    }

    override fun isEnabled(): Boolean = this.enabled

    override fun getUsername(): String = this.email

    override fun isCredentialsNonExpired(): Boolean = true

    override fun getPassword(): String = this.passwordHash

    override fun isAccountNonExpired(): Boolean = true

    override fun isAccountNonLocked(): Boolean = true

    class Builder {

        private var id: String = ""
        private var identifier: String = ""
        private var username: String = ""
        private var password: String = ""
        private var enabled: Boolean = false
        private var roles: List<RoleEnum> = emptyList()

        fun identifier(identifier: String): Builder {
            this.identifier = identifier
            return this
        }

        fun username(username: String): Builder {
            this.username = username
            return this
        }

        fun password(password: String): Builder {
            this.password = BCryptPasswordEncoder().encode(password)
            return this
        }

        fun enabled(enabled: Boolean): Builder {
            this.enabled = enabled
            return this
        }

        fun roleUser(): Builder {
            this.roles = listOf(RoleEnum.USER)
            return this
        }

        fun roleAdmin(): Builder {
            this.roles = listOf(RoleEnum.ADMIN)
            return this
        }

        fun build() = UserEntity(id, identifier, username, password, enabled, roles)
    }

}
