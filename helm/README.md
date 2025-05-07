
## Install Persistent Volumes & Secrets

```
kubectl apply -f helm/pvcs/postgres-pvc.yml
kubectl apply -f helm/pvcs/vault-pvc.yml

kubectl apply -f helm/config/postgres-secret.yml
```
