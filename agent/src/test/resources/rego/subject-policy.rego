package system

default main = false

main {
    input.credentialData.credentialSubject.id == input.parameter.user
}