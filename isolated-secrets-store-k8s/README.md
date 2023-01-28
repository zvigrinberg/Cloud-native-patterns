# Isolated Secured Secrets Store

## Goal - To create an infrastructural solution to a secure service that holds and serve sensitive data.

### Objectives: 

- Isolates the service from all the world, except selected clients that need to consume its service.
- Place a mechanism For Authentication and Authorization.

### Prerequisites

1. Access to a k8s Cluster.
2. Istio installed on it, if not installed, [Follow instructions here](https://istio.io/latest/docs/setup/getting-started/)
3. jq binary for manipulating json files.
4. Golang installed, [Get it here if you don't have](https://go.dev/dl/)
5. jwt token creator, signer and verifier command line tool, [Get it Here](https://github.com/golang-jwt/jwt/tree/main/cmd/jwt), Instructions to quickly install it and set it up on system PATH:
   ```shell
   cd /tmp
   git clone git@github.com:golang-jwt/jwt.git
   cd jwt/cmd/jwt
   go build -o jwt main.go
   cp ./jwt ~/bin
   ```
6. Download NodeJs , according to your [Platform](https://nodejs.org/en/download/)
7. pem to jwk(Json Web Key) convertor, to convert private + public keys from pem format to jwk format: 
    ```shell
     sudo npm install -g pem-jwk
    ```

### Create Keys ,JWKS and JWT
1. Create directory for demo keys
   ```shell
   mkdir -p demo-keys
   ```
2. Create a private key:
    ```shell
    openssl genrsa -out demo-keys/private.pem 4096
    ```
3. Creat a public key using the private key:
   ```shell
    openssl rsa -in  demo-keys/private.pem -out demo-keys/public.pem -pubout
   ```
   
4. Create a certificate
   ```shell
   openssl req -x509 -key demo-keys/private.pem -subj /CN=redhat.example.com  -days 3000 -out demo-keys/cert.pem
   ```

5. Create a JWKS file (JSON Web Key Set) using pem-jwk utility, This will be used to validate JWT by Istio 
   ```shell
   mkdir -p jwt
   ssh-keygen -e -m pkcs8 -f demo-keys/private.pem | pem-jwk | jq  '{kid: "rsaKey", kty: .kty , use: "sig", n: .n , e: .e }' | jq '{ "keys": [.] }' | jq -c . > ./jwt/jkws-demo.json   
   ```

6. Create A JWT using go jwt utility 
   ```shell
   echo {\"exp\": 4685989700, \"cloud-native\": \"true\", \"iat\": 1674389501, \"iss\": \"zgrinber@redhat.com\", \"sub\": \"zgrinber@redhat.com\"} | jwt -key demo-keys/private.pem -alg RS256 -sign - -header 'kid=rsaKey' -header 'alg=RS256' > ./jwt/demo.jwt
   ```
 
### Build Application image

1. Using your favorite Containers Engine tool(Podman/Docker/Buildah), Build the Application image:
```shell
podman build -t quay.io/zgrinber/manifests.secrets-store:1 . 
```
2. Connect to kubernetes Cluster.

3. If you don't have Istio installed on the cluster, kindly install it using the instructions [here](https://istio.io/latest/docs/setup/getting-started/)

4. Create 2 namespaces, one `secrets` , `consuming-test`
```shell
kubectl create namespace secrets
kubectl create namespace consuming-test
```
5. Label Both namespaces with istio-injection=enabled in order to inject envoy proxy side-cars containers to pods in the namespaces:
```shell
kubectl label namespace secrets istio-injection=enabled
kubectl label namespace consuming-test istio-injection=enabled

```

6. Deploy secrets-store application to k8s:
```shell
kustomize build manifests/ | kubectl apply -f - -n secrets
```

7. Check that all resources defined and that pod is up and running:
```shell
kubectl get all -n secrets
```
8. Run a pod with busybox, to be client that will consume endpoints from the secrets-store application:
```shell
kubectl run rest-test --image=busybox sleep infinity  -n consuming-test 
```
