package system

default main = false

main {
    input.motherId == data.parent[0].id
    input.fatherId == data.parent[1].id
}