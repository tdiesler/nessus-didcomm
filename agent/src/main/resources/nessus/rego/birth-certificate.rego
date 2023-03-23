package system

default main = false

main {
    input.credentialData.credentialSubject.parent[0].id == input.parameter.motherId
    input.credentialData.credentialSubject.parent[1].id == input.parameter.fatherId
}