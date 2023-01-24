# Transparently Encrypt/Decrypt Secrets k8s

## Objectives
 - Create and store secrets Encrypted in k8s.
 - Provide a solution to keep secrets encrypted in k8s etcd, but decrypt them only for using by applications in pods.
 - The solution must transparent to the application, so the application is not even aware of  that the secrets are encrypted.


## Proposed solution.
 - Secrets will be created encrypted using symmetric encryption, by using an agreed key. 
 - Use init container to be injected using SMP (Strategic merge patch) to deployment' pod template.
 - The init container will save copy of encrypted data in a shared volume(emptyDir volume) of the pod, will decrypt the values, and it will saved to secret, just before the pod' application container will mount the secrets to environment variables/volumes.
 - When init container will finish, the  application container will start up, a side-car container also will run in parallel, it will wait few seconds and will re-encrypt the secret with the encrypted data saved on the shared volume.
  
 
## Assumption and Constraints

- This procedure assumes that each secret is for one deployment in the namespace, and not shared between several deployments (otherwise procedure need to be applied to all, and there could be race conditions between the pods - over the secret)

## Implementation

### Prerequisites 

- We will use `kustomize` , for injecting to a demo deployment, a side-car container, init container and a shared volume to any given deployment.
  it's already included both in kubectl and oc (`kustomize` subcommand).
- The shared volume will be shared between init container and side-car container, and will be relevant and the data will last for the period of the lifecycle of the pod
- We will use `ccrypt` encryption/decryption utility, which using symmetric key encryption using cipher AES256, which can be downloaded from the [following site](https://ccrypt.sourceforge.net/) according to your platform, or installed directly with RPM
  ```shell
  sudo rpm -i http://ccrypt.sourceforge.net/download/1.11/ccrypt-1.11-1.x86_64.rpm
  ```
- I've built in advance an image with ccrypt and oc cli so the initContainer and side-car will be able to achieve our objectives, you can rebuild using [this Dockerfile](./Dockerfile) or use it directly 
  in the following public repo quay.io/zgrinber/installer:4.10
- The side-car and init container image will also have `ccrypt` tool and `oc` CLI tool.
- the side-car and init container need to have access to secrets( read, modify ), so for simplicity we will give to `default` serviceAccount in the project the predefined `secretshare` clusterRole
- Need to download `yq cli` tool to parse and query yaml files, can be [downloaded here](https://github.com/mikefarah/yq/releases)

### Procedure Demo

1. Create New Project to work on
```shell
 oc new-project encrypt-secrets
```

2. Add permissions for default SA to read and modify Secrets 
```shell
oc adm policy add-cluster-role-to-user secretshare -z default
```
3. Create an environment file containing secrets keys and values: 
```properties
token=someTokenValue
password=somePasswordValue
secret=someSecretValue
confidential=someConfidentialValue
```

```shell
cat > temp-env-file.env << EOF
token=someTokenValue
password=somePasswordValue
secret=someSecretValue
confidential=someConfidentialValue
EOF
```

4. Create a temp secret with environment file just created:
```shell
oc create secret generic temp-secret --from-env-file=temp-env-file.env -n default
```

5. extract the secrets to a format of filename=key and content=value:
```shell
oc extract secret/temp-secret -n default --to=./gen-secrets
## Now delete temp secret
oc delete secret temp-secret -n default 
```
6. Read an encryption key from input(Whatever text value)
```shell
read ENC_KEY
```

7. Save this encryption key to a file
```shell
echo token=$ENC_KEY > ./gen-secrets/token.env
```

8. Encrypt all values of extracted files
```shell
cd gen-secrets
for i in $(ls | grep -v -E  'kustomization|token.env'); do ccrypt -e -K $ENC_KEY  $i; mv $i.cpt $i; done
cd ..
```
9. deploy the application using kustomize:
```shell
kustomize build . | oc apply -f -
# If have kustomize cli, then run
kustomize build . | oc apply -f -
# otherwise
oc kustomize  . | oc apply -f -

secret/encrypt-token-secret-9f27k27cmg created
secret/secret-data created
deployment.apps/keep-secrets-encrypted-app created
```
10. Track and watch for application that is up, running and ready
```shell
oc get pods -w
[zgrinber@zgrinber transparent-encrypting-k8s-secrets]$ oc get pods -w
NAME                                         READY   STATUS     RESTARTS   AGE
keep-secrets-encrypted-app-6495cfdff-fdzs6   0/2     Init:0/1   0          3s
keep-secrets-encrypted-app-6495cfdff-fdzs6   0/2     Init:0/1   0          3s
keep-secrets-encrypted-app-6495cfdff-fdzs6   0/2     PodInitializing   0          8s
keep-secrets-encrypted-app-6495cfdff-fdzs6   2/2     Running           0          10s

```
11. Check that environment variables of application container in pod are mounted in plain-text, as needed and expected:
```shell
oc get pod | grep -v NAME | awk '{print $1}' | xargs -i oc exec {} -c container-1 env | grep Value
```
Output:
```shell
kubectl exec [POD] [COMMAND] is DEPRECATED and will be removed in a future version. Use kubectl exec [POD] -- [COMMAND] instead.
confidential=someConfidentialValue
password=somePasswordValue
secret=someSecretValue
token=someTokenValue
```
12. Checks that secret `secret-data` which was generated is with encrypted meaningless data
```shell
oc get secrets secret-data -o yaml  | yq .data | awk -F : '{print $2}' | xargs -i  sh -c "echo -n {}  | base64 -d ; echo" 
```
Output:
```shell
�.(V%�c������"����4�%�5��|����|�Ev,�J���I�
�<�;h�X�FI�B?� ��FǕRy�Y_        �����?O�7?h��
(��j�'B��gm�m��({5T�rhF����j�Ih�j��L[��)
�Ӂw*N��-���#i}��V��>�����ܫ�0c�`4��C��   �
```

13. Now scale up deployment to 2 replicas now and watch new pods scaled up:
```shell
 oc scale deployment keep-secrets-encrypted-app --replicas=2
 oc get pods -w 
```
Output:
```shell
NAME                                         READY   STATUS     RESTARTS   AGE
keep-secrets-encrypted-app-6495cfdff-fdzs6   2/2     Running    0          12m
keep-secrets-encrypted-app-6495cfdff-psjqr   0/2     Init:0/1   0          1s
keep-secrets-encrypted-app-6495cfdff-psjqr   0/2     Init:0/1   0          2s
keep-secrets-encrypted-app-6495cfdff-psjqr   0/2     Init:0/1   0          2s
keep-secrets-encrypted-app-6495cfdff-psjqr   0/2     PodInitializing   0          8s
keep-secrets-encrypted-app-6495cfdff-psjqr   2/2     Running           0          10s
```

14. Repeat steps 11 + 12 to see that environment variables are as expected in new pod and that secret is still encrypted.
