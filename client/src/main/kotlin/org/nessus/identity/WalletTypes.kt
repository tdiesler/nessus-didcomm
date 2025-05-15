package org.nessus.identity

// Authentication ------------------------------------------------------------------------------------------------------

enum class LoginType(val type: String) { EMAIL("email") }

data class LoginParams(val type: LoginType, val email: String, val password: String) {
    fun toAuthLoginRequest() : LoginRequest {
        return LoginRequest(type.type, email, password)
    }
}

data class RegisterUserParams(val type: LoginType, val name: String, val email: String, val password: String) {
    fun toAuthRegisterRequest() : RegisterUserRequest {
        return RegisterUserRequest(type.type, name, email, password)
    }
}

// Keys ----------------------------------------------------------------------------------------------------------------

data class Key(val id: String, val algorithm: String)
