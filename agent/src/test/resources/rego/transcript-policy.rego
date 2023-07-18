package system

default main = false

main {
    input.credentialData.credentialSubject.status == input.parameter.status
    to_number(input.credentialData.credentialSubject.average) >= input.parameter.average
}