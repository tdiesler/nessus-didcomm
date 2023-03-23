package system

default main = false

main {
    input.credentialData.credentialSubject.id == input.parameter.minorId
    input.credentialData.credentialSubject.guardian == input.parameter.guardianId
}