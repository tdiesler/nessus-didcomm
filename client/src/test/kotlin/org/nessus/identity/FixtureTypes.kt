package org.nessus.identity

open class User(val name: String, val email: String, val password: String) {
    fun toLoginParams() : LoginParams {
        return LoginParams(LoginType.EMAIL, email, password)
    }
    fun toRegisterUserParams() : RegisterUserParams {
        return RegisterUserParams(LoginType.EMAIL, name, email, password)
    }
}

object Alice : User("Alice", "alice@email.com", "password")
object Max : User("Max Mustermann", "user@email.com", "password")
