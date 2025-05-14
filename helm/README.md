
## Install Persistent Volumes & Secrets

```
kubectl apply -f helm/pvcs/postgres-pvc.yml

kubectl create secret generic postgres-secret \
  --from-literal=POSTGRES_USER=postgres \
  --from-literal=POSTGRES_PASSWORD=postgres
```

## Install Identity Service

```
helm upgrade --install identity ./helm -f ./helm/values-services-local.yaml
```
