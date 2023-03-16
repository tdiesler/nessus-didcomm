package system

default main = false

main {
    input.agentId == data.agent
    input.participantId == data.participant
}