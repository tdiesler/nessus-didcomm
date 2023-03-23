package system

default main = false

main {
    input.credentialData.credentialSubject.spouse[0].id == input.parameter.firstId
    input.credentialData.credentialSubject.spouse[1].id == input.parameter.secondId
}