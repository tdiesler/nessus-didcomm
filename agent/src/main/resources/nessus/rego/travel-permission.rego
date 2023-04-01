package system

default main = false

main {
    input.credentialData.credentialSubject.id == input.parameter.guardianId
    input.credentialData.credentialSubject.minor == input.parameter.minorId
}