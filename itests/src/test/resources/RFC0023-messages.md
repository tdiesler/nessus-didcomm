### RFC 0023 Establishing Connections with DID Exchange

### Bob creates an Out-of-Band Invitation

Req: POST http://0.0.0.0:9030/agent/command/out-of-band/send-invitation-message/ {"data": { "use_public_did": false }}
Res: 200

```json
{
  "invi_msg_id": "baff6b26-a2e6-482d-a150-4f622c884f6d",
  "invitation": {
    "@id": "baff6b26-a2e6-482d-a150-4f622c884f6d",
    "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/out-of-band/1.0/invitation",
    "handshake_protocols": [
      "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0",
      "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0"
    ],
    "label": "camel.Bob",
    "services": [
      {
        "id": "#inline",
        "type": "did-communication",
        "recipientKeys": [
          "did:key:z6Mkte15Pk8GgtiyP5igMDKmnHZpr9m4F1HCJWLhBDZn7s8p"
        ],
        "serviceEndpoint": "http://host.docker.internal:9031"
      }
    ]
  },
  "invitation_url": "http://host.docker.internal:9031?oob=eyJAdHlwZSI6ICJkaWQ6c292OkJ6Q2JzTlloTXJqSGlxWkRUVUFTSGc7c3BlYy9vdXQtb2YtYmFuZC8xLjAvaW52aXRhdGlvbiIsICJAaWQiOiAiYmFmZjZiMjYtYTJlNi00ODJkLWExNTAtNGY2MjJjODg0ZjZkIiwgInNlcnZpY2VzIjogW3siaWQiOiAiI2lubGluZSIsICJ0eXBlIjogImRpZC1jb21tdW5pY2F0aW9uIiwgInJlY2lwaWVudEtleXMiOiBbImRpZDprZXk6ejZNa3RlMTVQazhHZ3RpeVA1aWdNREttbkhacHI5bTRGMUhDSldMaEJEWm43czhwIl0sICJzZXJ2aWNlRW5kcG9pbnQiOiAiaHR0cDovL2hvc3QuZG9ja2VyLmludGVybmFsOjkwMzEifV0sICJoYW5kc2hha2VfcHJvdG9jb2xzIjogWyJkaWQ6c292OkJ6Q2JzTlloTXJqSGlxWkRUVUFTSGc7c3BlYy9kaWRleGNoYW5nZS8xLjAiLCAiZGlkOnNvdjpCekNic05ZaE1yakhpcVpEVFVBU0hnO3NwZWMvY29ubmVjdGlvbnMvMS4wIl0sICJsYWJlbCI6ICJjYW1lbC5Cb2IifQ==",
  "oob_id": "ca77c567-16b7-419c-8529-202d1bd7f546",
  "state": "invitation-sent",
  "trace": false
}
```

### Bob accepts the Invitation

Req: GET http://0.0.0.0:9030/agent/response/did-exchange/baff6b26-a2e6-482d-a150-4f622c884f6d
Res: 200

```json
{
  "accept": "auto",
  "connection_id": "b28f0802-e57c-401f-bdcd-1975fbb3da68",
  "connection_protocol": "didexchange/1.0",
  "created_at": "2022-12-25T11:32:33.312245Z",
  "invitation_key": "FBk2oVsqMMEWGasyfeMvwC1q2aVCq82qcVRmLwbmCeMS",
  "invitation_mode": "once",
  "invitation_msg_id": "baff6b26-a2e6-482d-a150-4f622c884f6d",
  "routing_state": "none",
  "state": "invitation-received",
  "their_role": "invitee",
  "updated_at": "2022-12-25T11:32:33.312245Z"
}
```

### Acme accepts the Invitation

Req: POST http://0.0.0.0:9020/agent/command/out-of-band/receive-invitation/
Res: 200

```json
{
  "data": {
    "@id": "baff6b26-a2e6-482d-a150-4f622c884f6d",
    "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/out-of-band/1.0/invitation",
    "handshake_protocols": [
      "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0",
      "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0"
    ],
    "label": "camel.Bob",
    "services": [
      {
        "id": "#inline",
        "type": "did-communication",
        "recipientKeys": [
          "did:key:z6Mkte15Pk8GgtiyP5igMDKmnHZpr9m4F1HCJWLhBDZn7s8p"
        ],
        "serviceEndpoint": "http://host.docker.internal:9031"
      }
    ],
    "use_existing_connection": false
  }
}
```

```json
{
  "accept": "manual",
  "connection_id": "b9f93698-f9cf-444c-aa1a-9ec417cc74e3",
  "connection_protocol": "didexchange/1.0",
  "created_at": "2022-12-25T11:32:33.910120Z",
  "invitation_key": "FBk2oVsqMMEWGasyfeMvwC1q2aVCq82qcVRmLwbmCeMS",
  "invitation_mode": "once",
  "invitation_msg_id": "baff6b26-a2e6-482d-a150-4f622c884f6d",
  "rfc23_state": "invitation-received",
  "routing_state": "none",
  "state": "invitation-received",
  "their_label": "camel.Bob",
  "their_role": "inviter",
  "updated_at": "2022-12-25T11:32:33.910120Z"
}
```

### Acme sends the DIDExchange request

Req: POST http://0.0.0.0:9020/agent/command/did-exchange/send-request/ {"id": "b9f93698-f9cf-444c-aa1a-9ec417cc74e3"}
Res: 200 

```json
{
  "accept": "manual",
  "connection_id": "b9f93698-f9cf-444c-aa1a-9ec417cc74e3",
  "connection_protocol": "didexchange/1.0",
  "created_at": "2022-12-25T11:32:33.910120Z",
  "invitation_key": "FBk2oVsqMMEWGasyfeMvwC1q2aVCq82qcVRmLwbmCeMS",
  "invitation_mode": "once",
  "invitation_msg_id": "baff6b26-a2e6-482d-a150-4f622c884f6d",
  "my_did": "JnbXpFwRgBrKqPpfvPDsE1",
  "request_id": "21784dff-cd0a-47f7-aa75-ec722491574f",
  "rfc23_state": "request-sent",
  "routing_state": "none",
  "state": "request-sent",
  "their_label": "camel.Bob",
  "their_role": "inviter",
  "updated_at": "2022-12-25T11:32:34.220431Z"
}
```

### Bob sends the DIDExchange response

Req: POST http://0.0.0.0:9030/agent/command/did-exchange/send-response/ {"id": "b28f0802-e57c-401f-bdcd-1975fbb3da68"}
Res: 200 

```json
{
  "accept": "auto",
  "connection_id": "b28f0802-e57c-401f-bdcd-1975fbb3da68",
  "connection_protocol": "didexchange/1.0",
  "created_at": "2022-12-25T11:32:33.312245Z",
  "invitation_key": "FBk2oVsqMMEWGasyfeMvwC1q2aVCq82qcVRmLwbmCeMS",
  "invitation_mode": "once",
  "invitation_msg_id": "baff6b26-a2e6-482d-a150-4f622c884f6d",
  "my_did": "9nfcmJRPJPtRZgwzr8CPRY",
  "request_id": "21784dff-cd0a-47f7-aa75-ec722491574f",
  "routing_state": "none",
  "state": "completed",
  "their_did": "JnbXpFwRgBrKqPpfvPDsE1",
  "their_label": "aca-py.Acme",
  "their_role": "invitee",
  "updated_at": "2022-12-25T11:32:34.559748Z"
}
```
