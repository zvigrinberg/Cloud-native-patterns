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
 
### Build Application image and deploy it.

1. Using your favorite Containers Engine tool(Podman/Docker/Buildah), Build the Application image:
```shell
podman build -t quay.io/zgrinber/manifests.secrets-store:1 . 
```
2. Connect to kubernetes Cluster.
  - If you're using minikube , you need to install cni plugin provider in the cluster, that will implement k8s' networking Policy functionality,  supported implementations are calico, cilium and flannel, I used cilium, you can create the minikube cluster with this command:
      ```shell
      minikube start --cni cilium
      ```

4. If you don't have Istio installed on the cluster, kindly install it using the instructions [here](https://istio.io/latest/docs/setup/getting-started/)

5. Create 2 namespaces, one `secrets` , `consuming-test`
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
9. Create Istio' RequestAuthentication Object to enable JWT authentication ( and validation according to JWKS that I've created earlier ) in secrets namespace:
```shell
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: "jwt-auth"
  namespace: secrets
spec:
  selector:
    matchLabels:
      app: secrets-store
  jwtRules:
  - issuer: "zgrinber@redhat.com"
    jwksUri: "https://raw.githubusercontent.com/zvigrinberg/Cloud-native-patterns/main/isolated-secrets-store-k8s/jwt/jkws-demo.json"
EOF
```
10. Now create Istio' AuthorizationPolicy to define rule which will permit only  a specific issuer and subject claims (in this case it's the same one) that must be presented in the jwt
```shell
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: require-jwt
  namespace: secrets
spec:
  selector:
    matchLabels:
      app: secrets-store
  action: ALLOW
  rules:
  - from:
    - source:
       requestPrincipals: ["zgrinber@redhat.com/zgrinber@redhat.com"]
EOF
```
11. Label consuming-test namespace with the right label so it will be able to access the secrets-store service in namespace secrets according to Constraint defined in network policy:
```shell
kubectl label namespace consuming-test accessSecretStore="true"
```
12. Create a client pod on the consuming-test namespace (which is opened to invoke secrets-store service in secrets namespace) and we'll try to access the secrets store from it
```shell
 kubectl run rest-test --image=busybox sleep infinity  -n consuming-test 
pod/rest-test created
```

13. Try to invoke the secrets-store service from the pod, without jwt
```shell
kubectl exec rest-test -n consuming-test sh -- wget http://secrets-store.secrets:8080/client/init -O -

Connecting to secrets-store.secrets:8080 (10.105.233.220:8080)
wget: server returned error: HTTP/1.1 403 Forbidden
command terminated with exit code 1
```
**Note: We got that we're not authorized, this is because we didn't specify an authorized JWT token, we'll do it right now**

14. Now pass into the request' Authorization Bearer header the JWT that we've created earlier:
```shell
export TOKEN=$(cat ./jwt/demo.jwt) ; kubectl exec rest-test -n consuming-test sh -- wget http://secrets-store.secrets:8080/client/init --header 'Authorization: Bearer '$TOKEN'' -S  -O -

Connecting to secrets-store.secrets:8080 (10.105.233.220:8080)
  HTTP/1.1 200 OK
  date: Sun, 29 Jan 2023 00:52:17 GMT
  content-length: 167
  content-type: text/plain; charset=utf-8
  x-envoy-upstream-service-time: 0
  server: istio-envoy
  connection: close
  x-envoy-decorator-operation: secrets-store.secrets.svc.cluster.local:8080/*
  
writing to stdout
-                    100% |********************************|   167  0:00:00 ETA
written to stdout
{"endpoints":[{"name":"TOKEN","url":"/client/v1/secret/TOKEN"},{"name":"PASSWORD","url":"/client/v1/secret/PASSWORD"},{"name":"CERT","url":"/client/v1/secret/CERT"}]}
```

15. Now let's prove that the JWT validation is actually working correctly against the JWKS file that we've configured for Istio RequestAuthentication, let's decode header and claims part of the jwt:
```shell
echo $TOKEN | awk -F . '{print $1"\n" $2}' | base64 -d
{"alg":"RS256","kid":"rsaKey","typ":"JWT"}{"cloud-native":"true","exp":4685989700,"iat":1674389501,"iss":"zgrinber@redhat.com","sub":"zgrinber@redhat.com"}
```
Now let's take this 2 parts , but without the secret part , and pass another invalid secret part , and see that it won't let us consume the service that way.

16. Try to invoke the endpoint in secrets-service with an invalidated JWT:
```shell
INVALID_TOKEN=$(echo $TOKEN | awk -F . '{print $1"."$2".abcdefghijklmnopqrstuvwxyz"}' | cat) ; kubectl exec rest-test -n consuming-test sh -- wget http://secrets-store.secrets:8080/client/init --header 'Authorization: Bearer '$INVALID_TOKEN'' -S  -O -
Connecting to secrets-store.secrets:8080 (10.105.233.220:8080)
  HTTP/1.1 401 Unauthorized
wget: server returned error: HTTP/1.1 401 Unauthorized
command terminated with exit code 1
```

17. OK, So from namespace consuming-test, we have communication to secrets namespace, and with the Right signed JWT (only with it) , we can actually consume data from secrets-store service.
    Now let's see what happend if we're trying to consume the service from default namespace:
```shell
kubectl run rest-test --image=busybox sleep infinity  -n default
pod/rest-test created
kubectl exec rest-test -n default sh -- wget http://secrets-store.secrets:8080/client/init -O -
Connecting to secrets-store.secrets:8080 (10.105.233.220:8080)
wget: error getting response: Connection reset by peer
command terminated with exit code 1
```
And we got that the networking from default to secrets namespace is blocked, as expected ( blocked by k8s network policy ). 