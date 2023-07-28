package system

default main = false

main {
    input.credentialData.credentialSubject.employee_status == input.parameter.employee_status
    to_number(input.credentialData.credentialSubject.salary) >= input.parameter.salary
}