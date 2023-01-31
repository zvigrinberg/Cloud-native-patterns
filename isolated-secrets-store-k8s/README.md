# Isolated Secured Secrets Store

## Goal - To create an infrastructural solution to a secure service that holds and serve sensitive data.

### Objectives: 

- Isolates the service from all the world, except selected clients that need to consume its service.
- Place a mechanism For Authentication and Authorization.

### Prerequisites

1. Access to a k8s Cluster.
2. Istio installed on it, if not installed, [Follow instructions here](https://istio.io/latest/docs/setup/getting-started/):
 
   **Note: If wants to run Istion with privileged escalation in order to sniff packets ( to see Auto mTLS in action), install istio with the following flag on cluster:** 
    ```shell
    istioctl install --set values.global.proxy.privileged=true
    ```
4. jq binary for manipulating json files.
5. Golang installed, [Get it here if you don't have](https://go.dev/dl/)
6. jwt token creator, signer and verifier command line tool, [Get it Here](https://github.com/golang-jwt/jwt/tree/main/cmd/jwt), Instructions to quickly install it and set it up on system PATH:
   ```shell
   cd /tmp
   git clone git@github.com:golang-jwt/jwt.git
   cd jwt/cmd/jwt
   go build -o jwt main.go
   cp ./jwt ~/bin
   ```
7. Download NodeJs , according to your [Platform](https://nodejs.org/en/download/)
8. pem to jwk(Json Web Key) convertor, to convert private + public keys from pem format to jwk format: 
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
kustomize build manifests/k8s | kubectl apply -f - -n secrets
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
```
Output:
```shell
Connecting to secrets-store.secrets:8080 (10.98.220.241:8080)
wget: server returned error: HTTP/1.1 403 Forbidden
command terminated with exit code 1
```
**Note: We got that we're not authorized, this is because we didn't specify an authorized JWT token, we'll do it right now**

14. Now pass into the request' Authorization Bearer header the JWT that we've created earlier:
```shell
export TOKEN=$(cat ./jwt/demo.jwt) ; kubectl exec rest-test -n consuming-test sh -- wget http://secrets-store.secrets:8080/client/init --header 'Authorization: Bearer '$TOKEN'' -S  -O -
```

Output:
```shell
written to stdout
{"endpoints":[{"name":"TOKEN","url":"/client/v1/secret/TOKEN"},{"name":"PASSWORD","url":"/client/v1/secret/PASSWORD"},{"name":"CERT","url":"/client/v1/secret/CERT"}]}
Connecting to secrets-store.secrets:8080 (10.105.233.220:8080)
  HTTP/1.1 200 OK
  date: Mon, 30 Jan 2023 09:08:46 GMT
  content-length: 167
  content-type: text/plain; charset=utf-8
  x-envoy-upstream-service-time: 0
  server: istio-envoy
  connection: close
  x-envoy-decorator-operation: secrets-store.secrets.svc.cluster.local:8080/*
  
writing to stdout
-                    100% |********************************|   167  0:00:00 ETA
```

15. Now let's enable mTLS traffic between consuming-test and secrets namespaces, by leveraging Istio's feature of  auto mTLS (Client + Server) , So we'll have pod to pod TLS encryption, so the origin side-car envoy proxy will encrypt the data, and the target envoy proxy will decrypt the data payload, and pass it to the backend application:
```shell
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1beta1                                    
kind: PeerAuthentication
metadata:
  name: "default"
  namespace: "secrets"
spec:
  mtls:
    mode: STRICT
EOF
```

16. The Response payload from section 14, is in the form of REST Architecture kind of constraint which is called [`HATEOAS`](https://en.wikipedia.org/wiki/HATEOAS) (Acronym for "Hypermedia as the Engine of Application State"), so let's take one of the endpoints and invoke it on the server:
```shell
export TOKEN=$(cat ./jwt/demo.jwt) ; kubectl exec rest-test -n consuming-test sh -- wget http://secrets-store.secrets:8080/client/v1/secret/TOKEN --header 'Authorization: Bearer '$TOKEN'' -S  -O -
```
Output:
```shell
{"secretName":"TOKEN","secretValue":"mysecrettoken"}
Connecting to secrets-store.secrets:8080 (10.98.220.241:8080)
  HTTP/1.1 200 OK
  date: Mon, 30 Jan 2023 09:18:18 GMT
  content-length: 53
  content-type: text/plain; charset=utf-8
  x-envoy-upstream-service-time: 0
  server: envoy
  connection: close
  
writing to stdout
-                    100% |********************************|    53  0:00:00 ETA
```

17. Let's prove that the payload sent encrypted, the hard way is to sniff the packets in the envoy proxy container when the packet intercepted, but there is an easy way how to do it in Istio, Side-car envoy proxy enrich the request before sends it to the target with a dedicated header called `X-Forwarded-Client-Cert`, So if we'll see that this Header exists in the logs of the backend application (I'm printing there the headers, for this purpose also), then it means that the request sent encrypted from pod to pod:
```shell
kubectl logs $(kubectl get pods -l app=secrets-store -n secrets -o=jsonpath="{..metadata.name}") -n secrets | tail -n 50 | grep REQUEST: -A 11 | grep Forwarded
```
Output:
```shell
X-Forwarded-Client-Cert: By=spiffe://cluster.local/ns/secrets/sa/default;Hash=21a228796296835400109189d50d26d1c55f67fd8d271340b94c983cd8e1bd5d;Subject="";URI=spiffe://cluster.local/ns/consuming-test/sa/default
X-Forwarded-Proto: http
```
18. Now let's prove that the JWT validation is actually working correctly against the JWKS file that we've configured for Istio RequestAuthentication, let's decode header and claims part of the jwt:
```shell
echo $TOKEN | awk -F . '{print $1"\n" $2}' | base64 -d
{"alg":"RS256","kid":"rsaKey","typ":"JWT"}{"cloud-native":"true","exp":4685989700,"iat":1674389501,"iss":"zgrinber@redhat.com","sub":"zgrinber@redhat.com"}
```
Now let's take this 2 parts , but without the secret part , and pass another invalid secret part , and see that it won't let us consume the service that way.

19. Try to invoke the endpoint in secrets-service with an invalidated JWT:
```shell
INVALID_TOKEN=$(echo $TOKEN | awk -F . '{print $1"."$2".abcdefghijklmnopqrstuvwxyz"}' | cat) ; kubectl exec rest-test -n consuming-test sh -- wget http://secrets-store.secrets:8080/client/init --header 'Authorization: Bearer '$INVALID_TOKEN'' -S  -O -
```
Output:
```shell
Connecting to secrets-store.secrets:8080 (10.105.233.220:8080)
  HTTP/1.1 401 Unauthorized
wget: server returned error: HTTP/1.1 401 Unauthorized
command terminated with exit code 1
```


20. OK, So from namespace consuming-test, we have communication to secrets namespace, and with the Right signed JWT (only with it) , we can actually consume data from secrets-store service.
    Now let's see what happend if we're trying to consume the service from default namespace:
```shell
kubectl run rest-test --image=busybox sleep infinity  -n default
kubectl exec rest-test -n default sh -- wget http://secrets-store.secrets:8080/client/init -O -
```

Output:
```shell
pod/rest-test created
Connecting to secrets-store.secrets:8080 (10.105.233.220:8080)
wget: error getting response: Connection reset by peer
command terminated with exit code 1
```
And we got that the networking from default to secrets namespace is blocked, as expected ( blocked by k8s network policy ). 

### Advanced: sniff packets in istio' envoy proxy side-car using tcpdump tool

1. First let's Disable Auto mTLS between sidecars, so we'll disable Auto mTLS at the namespace level on both namespaces:
```shell
kubectl apply -f - <<EOF
apiVersion: security.istio.io/v1beta1                                    
kind: PeerAuthentication
metadata:
  name: "default"
  namespace: "secrets"
spec:
  mtls:
    mode: DISABLE
---
apiVersion: security.istio.io/v1beta1                                    
kind: PeerAuthentication
metadata:
  name: "default"
  namespace: "consuming-test"
spec:
  mtls:
    mode: DISABLE
EOF
```

2. Open new terminal windows , and sniff packets (port 8080 only) on the client pod' side car container:
```shell
kubectl exec  rest-test -n consuming-test sh -c istio-proxy -- sudo tcpdump -i eth0 port 8080 -XX
```

3. In the previous terminal window, run HTTP Get request to secrets-store service from the client pod' application container:
```shell
export TOKEN=$(cat ./jwt/demo.jwt) ; kubectl exec rest-test -n consuming-test sh -- wget http://secrets-store.secrets:8080/client/v1/secret/TOKEN --header 'Authorization: Bearer '$TOKEN'' -S  -O -
```

4. Go to the sniffer terminal now, and looks the intercepted packets:
```shell
15:14:48.629685 IP rest-test.35228 > 10-244-0-103.secrets-store.secrets.svc.cluster.local.http-alt: Flags [P.], seq 2078:4155, ack 1088, win 502, options [nop,nop,TS val 2668157115 ecr 275546347], length 2077: HTTP: GET /client/v1/secret/TOKEN HTTP/1.1
	0x0000:  7e43 cf19 d33d da84 1418 1f2c 0800 4500  ~C...=.....,..E.
	0x0010:  0851 7a8e 4000 4006 a1c4 0af4 0006 0af4  .Qz.@.@.........
	0x0020:  0067 899c 1f90 4f1d db57 1cf1 b891 8018  .g....O..W......
	0x0030:  01f6 1e98 0000 0101 080a 9f08 d8bb 106c  ...............l
	0x0040:  80eb 4745 5420 2f63 6c69 656e 742f 7631  ..GET./client/v1
	0x0050:  2f73 6563 7265 742f 544f 4b45 4e20 4854  /secret/TOKEN.HT
	0x0060:  5450 2f31 2e31 0d0a 686f 7374 3a20 7365  TP/1.1..host:.se
	0x0070:  6372 6574 732d 7374 6f72 652e 7365 6372  crets-store.secr
	0x0080:  6574 733a 3830 3830 0d0a 7573 6572 2d61  ets:8080..user-a
	0x0090:  6765 6e74 3a20 5767 6574 0d0a 6175 7468  gent:.Wget..auth
	0x00a0:  6f72 697a 6174 696f 6e3a 2042 6561 7265  orization:.Beare
	0x00b0:  7220 6579 4a68 6247 6369 4f69 4a53 557a  r.eyJhbGciOiJSUz
	0x00c0:  4931 4e69 4973 496d 7470 5a43 4936 496e  I1NiIsImtpZCI6In
	0x00d0:  4a7a 5955 746c 6553 4973 496e 5235 6343  JzYUtleSIsInR5cC
	0x00e0:  4936 496b 7058 5643 4a39 2e65 794a 6a62  I6IkpXVCJ9.eyJjb
	0x00f0:  4739 315a 4331 7559 5852 7064 6d55 694f  G91ZC1uYXRpdmUiO
	0x0100:  694a 3063 6e56 6c49 6977 695a 5868 7749  iJ0cnVlIiwiZXhwI
	0x0110:  6a6f 304e 6a67 314f 5467 354e 7a41 774c  jo0Njg1OTg5NzAwL
	0x0120:  434a 7059 5851 694f 6a45 324e 7a51 7a4f  CJpYXQiOjE2NzQzO
	0x0130:  446b 314d 4445 7349 6d6c 7a63 7949 3649  Dk1MDEsImlzcyI6I
	0x0140:  6e70 6e63 6d6c 7559 6d56 7951 484a 6c5a  npncmluYmVyQHJlZ
	0x0150:  4768 6864 4335 6a62 3230 694c 434a 7a64  GhhdC5jb20iLCJzd
	0x0160:  5749 694f 694a 365a 334a 7062 6d4a 6c63  WIiOiJ6Z3JpbmJlc
	0x0170:  6b42 795a 5752 6f59 5851 7559 3239 7449  kByZWRoYXQuY29tI
	0x0180:  6e30 2e58 6430 5073 462d 3756 6870 2d4f  n0.Xd0PsF-7Vhp-O
	0x0190:  4b76 5472 626e 4a6d 7463 5332 5579 634f  KvTrbnJmtcS2UycO
	0x01a0:  3463 7545 7a78 5069 7472 452d 756e 6b7a  4cuEzxPitrE-unkz
	0x01b0:  5a71 3045 3132 715f 3735 5830 466b 5773  Zq0E12q_75X0FkWs
	0x01c0:  3169 4f4b 767a 7747 4778 4d35 4952 4265  1iOKvzwGGxM5IRBe
	0x01d0:  3071 3169 4f71 4643 7775 3153 6662 6376  0q1iOqFCwu1Sfbcv
	0x01e0:  3248 3263 504c 3876 3065 386f 2d63 587a  2H2cPL8v0e8o-cXz
	0x01f0:  706e 7034 476e 4d37 3842 6146 5977 366a  pnp4GnM78BaFYw6j
	0x0200:  6342 5451 4c58 536f 3172 6b38 3168 4e4b  cBTQLXSo1rk81hNK
	0x0210:  3875 7233 7457 7250 6d4d 7457 535a 5854  8ur3tWrPmMtWSZXT
	0x0220:  7253 4957 6a73 5366 3142 5132 5a4b 6e76  rSIWjsSf1BQ2ZKnv
	0x0230:  3141 7172 757a 6e4e 3030 6a68 4951 4c53  1AqruznN00jhIQLS
	0x0240:  5763 5f38 7144 4234 5578 7650 667a 7366  Wc_8qDB4UxvPfzsf
	0x0250:  3150 324c 2d72 7761 526b 4631 4478 346f  1P2L-rwaRkF1Dx4o
	0x0260:  5833 5431 6b52 5f4b 646e 5533 5962 6976  X3T1kR_KdnU3Ybiv
	0x0270:  347a 736c 4f4a 6a74 7a63 476f 304f 344d  4zslOJjtzcGo0O4M
	0x0280:  6765 3644 4659 494a 374b 6559 4976 7a67  ge6DFYIJ7KeYIvzg
	0x0290:  4431 3054 4c74 7576 5438 676f 5a58 4966  D10TLtuvT8goZXIf
	0x02a0:  4d4f 6b4c 7073 7750 4675 4a7a 5135 674d  MOkLpswPFuJzQ5gM
	0x02b0:  5541 4f4b 426b 3133 3856 3750 7472 4f6f  UAOKBk138V7PtrOo
	0x02c0:  5638 354e 7a49 586b 3532 4a43 5a75 5454  V85NzIXk52JCZuTT
	0x02d0:  394b 6c4f 3952 6f56 504f 6d75 4d51 706c  9KlO9RoVPOmuMQpl
	0x02e0:  6430 314c 5f34 6171 6e6d 3457 4c50 6935  d01L_4aqnm4WLPi5
	0x02f0:  6a65 6277 3651 3244 694b 546f 5430 3649  jebw6Q2DiKToT06I
	0x0300:  694a 6b47 7233 4830 6350 6573 5837 506d  iJkGr3H0cPesX7Pm
	0x0310:  5231 6231 7938 334a 4156 6e42 7951 7557  R1b1y83JAVnByQuW
	0x0320:  5671 7949 5736 5a33 3668 4976 4e67 4e64  VqyIW6Z36hIvNgNd
	0x0330:  757a 3742 5f5f 7834 6d54 3759 7765 7842  uz7B__x4mT7YwexB
	0x0340:  3273 4836 7542 4f71 5243 4b6d 4f72 3238  2sH6uBOqRCKmOr28
	0x0350:  6263 4a49 5749 7172 6e55 616a 6558 4757  bcJIWIqrnUajeXGW
	0x0360:  545a 7671 6d59 4b2d 537a 6c33 6b76 6c6b  TZvqmYK-Szl3kvlk
	0x0370:  4169 624b 6731 6c65 5376 4d59 5337 5549  AibKg1leSvMYS7UI
	0x0380:  7a42 5347 4453 7152 6f77 6643 4731 7748  zBSGDSqRowfCG1wH
	0x0390:  6e67 7a4f 6464 4f5a 4672 6f72 356c 4561  ngzOddOZFror5lEa
	0x03a0:  4c5a 664e 6950 3376 7459 4961 7839 4e6e  LZfNiP3vtYIax9Nn
	0x03b0:  754a 5f61 5a73 4e37 664c 6a54 5663 6174  uJ_aZsN7fLjTVcat
	0x03c0:  4177 6e4a 2d65 5854 3550 5264 486e 6148  AwnJ-eXT5PRdHnaH
	0x03d0:  7a76 6159 7744 4e4f 4c36 6d30 4753 696e  zvaYwDNOL6m0GSin
	0x03e0:  3848 7078 504b 4a33 5077 3434 554d 4169  8HpxPKJ3Pw44UMAi
	0x03f0:  3061 4948 6567 782d 5263 7239 314d 474c  0aIHegx-Rcr91MGL
	0x0400:  6148 4870 5571 5457 5251 307a 2d57 3235  aHHpUqTWRQ0z-W25
	0x0410:  7572 4c38 5570 4938 6832 516e 6857 4e50  urL8UpI8h2QnhWNP
	0x0420:  636f 4575 6536 335f 2d56 534a 4c63 0d0a  coEue63_-VSJLc..
	0x0430:  782d 666f 7277 6172 6465 642d 7072 6f74  x-forwarded-prot
	0x0440:  6f3a 2068 7474 700d 0a78 2d72 6571 7565  o:.http..x-reque
	0x0450:  7374 2d69 643a 2033 6164 6336 6235 622d  st-id:.3adc6b5b-
	0x0460:  6563 3839 2d34 3262 352d 3834 6237 2d37  ec89-42b5-84b7-7
	0x0470:  6431 3664 6531 6232 6566 330d 0a78 2d65  d16de1b2ef3..x-e
	0x0480:  6e76 6f79 2d64 6563 6f72 6174 6f72 2d6f  nvoy-decorator-o
	0x0490:  7065 7261 7469 6f6e 3a20 7365 6372 6574  peration:.secret
	0x04a0:  732d 7374 6f72 652e 7365 6372 6574 732e  s-store.secrets.
	0x04b0:  7376 632e 636c 7573 7465 722e 6c6f 6361  svc.cluster.loca
	0x04c0:  6c3a 3830 3830 2f2a 0d0a 782d 656e 766f  l:8080/*..x-envo
	0x04d0:  792d 7065 6572 2d6d 6574 6164 6174 613a  y-peer-metadata:
	0x04e0:  2043 6830 4b44 6b46 5155 4639 4454 3035  .Ch0KDkFQUF9DT05
	0x04f0:  5551 556c 4f52 564a 5445 6773 6143 584a  UQUlORVJTEgsaCXJ
	0x0500:  6c63 3351 7464 4756 7a64 416f 6143 6770  lc3QtdGVzdAoaCgp
	0x0510:  4454 4656 5456 4556 5358 306c 4545 6777  DTFVTVEVSX0lEEgw
	0x0520:  6143 6b74 3159 6d56 7962 6d56 305a 584d  aCkt1YmVybmV0ZXM
	0x0530:  4b48 416f 4d53 5535 5456 4546 4f51 3056  KHAoMSU5TVEFOQ0V
	0x0540:  6653 5642 5445 6777 6143 6a45 774c 6a49  fSVBTEgwaCjEwLjI
	0x0550:  304e 4334 774c 6a59 4b47 516f 4e53 564e  0NC4wLjYKGQoNSVN
	0x0560:  5553 5539 6656 6b56 5355 306c 5054 6849  USU9fVkVSU0lPThI
	0x0570:  4947 6759 784c 6a45 324c 6a45 4b71 5145  IGgYxLjE2LjEKqQE
	0x0580:  4b42 6b78 4251 6b56 4d55 784b 6541 5371  KBkxBQkVMUxKeASq
	0x0590:  6241 516f 5343 674e 7964 5734 5343 786f  bAQoSCgNydW4SCxo
	0x05a0:  4a63 6d56 7a64 4331 305a 584e 3043 6951  JcmVzdC10ZXN0CiQ
	0x05b0:  4b47 584e 6c59 3356 7961 5852 354c 6d6c  KGXNlY3VyaXR5Lml
	0x05c0:  7a64 476c 764c 6d6c 764c 3352 7363 3031  zdGlvLmlvL3Rsc01
	0x05d0:  765a 4755 5342 786f 4661 584e 3061 5738  vZGUSBxoFaXN0aW8
	0x05e0:  4b4c 676f 6663 3256 7964 6d6c 6a5a 5335  KLgofc2VydmljZS5
	0x05f0:  7063 3352 7062 7935 7062 7939 6a59 5735  pc3Rpby5pby9jYW5
	0x0600:  7662 6d6c 6a59 5777 7462 6d46 745a 5249  vbmljYWwtbmFtZRI
	0x0610:  4c47 676c 795a 584e 304c 5852 6c63 3351  LGglyZXN0LXRlc3Q
	0x0620:  4b4c 776f 6a63 3256 7964 6d6c 6a5a 5335  KLwojc2VydmljZS5
	0x0630:  7063 3352 7062 7935 7062 7939 6a59 5735  pc3Rpby5pby9jYW5
	0x0640:  7662 6d6c 6a59 5777 7463 6d56 3261 584e  vbmljYWwtcmV2aXN
	0x0650:  7062 3234 5343 426f 4762 4746 305a 584e  pb24SCBoGbGF0ZXN
	0x0660:  3043 686f 4b42 3031 4655 3068 6653 5551  0ChoKB01FU0hfSUQ
	0x0670:  5344 786f 4e59 3278 3163 3352 6c63 6935  SDxoNY2x1c3Rlci5
	0x0680:  7362 324e 6862 416f 5443 6752 4f51 5531  sb2NhbAoTCgROQU1
	0x0690:  4645 6773 6143 584a 6c63 3351 7464 4756  FEgsaCXJlc3QtdGV
	0x06a0:  7a64 416f 6443 676c 4f51 5531 4655 3142  zdAodCglOQU1FU1B
	0x06b0:  4251 3055 5345 426f 4f59 3239 7563 3356  BQ0USEBoOY29uc3V
	0x06c0:  7461 5735 6e4c 5852 6c63 3351 4b53 416f  taW5nLXRlc3QKSAo
	0x06d0:  4654 3164 4f52 5649 5350 786f 3961 3356  FT1dORVISPxo9a3V
	0x06e0:  695a 584a 755a 5852 6c63 7a6f 764c 3246  iZXJuZXRlczovL2F
	0x06f0:  7761 584d 7664 6a45 7662 6d46 745a 584e  waXMvdjEvbmFtZXN
	0x0700:  7759 574e 6c63 7939 6a62 3235 7a64 5731  wYWNlcy9jb25zdW1
	0x0710:  7062 6d63 7464 4756 7a64 4339 7762 3252  pbmctdGVzdC9wb2R
	0x0720:  7a4c 334a 6c63 3351 7464 4756 7a64 416f  zL3Jlc3QtdGVzdAo
	0x0730:  5843 6846 5154 4546 5552 6b39 5354 5639  XChFQTEFURk9STV9
	0x0740:  4e52 5652 4252 4546 5551 5249 434b 6741  NRVRBREFUQRICKgA
	0x0750:  4b48 416f 4e56 3039 5353 3078 5051 5552  KHAoNV09SS0xPQUR
	0x0760:  6654 6b46 4e52 5249 4c47 676c 795a 584e  fTkFNRRILGglyZXN
	0x0770:  304c 5852 6c63 3351 3d0d 0a78 2d65 6e76  0LXRlc3Q=..x-env
	0x0780:  6f79 2d70 6565 722d 6d65 7461 6461 7461  oy-peer-metadata
	0x0790:  2d69 643a 2073 6964 6563 6172 7e31 302e  -id:.sidecar~10.
	0x07a0:  3234 342e 302e 367e 7265 7374 2d74 6573  244.0.6~rest-tes
	0x07b0:  742e 636f 6e73 756d 696e 672d 7465 7374  t.consuming-test
	0x07c0:  7e63 6f6e 7375 6d69 6e67 2d74 6573 742e  ~consuming-test.
	0x07d0:  7376 632e 636c 7573 7465 722e 6c6f 6361  svc.cluster.loca
	0x07e0:  6c0d 0a78 2d65 6e76 6f79 2d61 7474 656d  l..x-envoy-attem
	0x07f0:  7074 2d63 6f75 6e74 3a20 310d 0a78 2d62  pt-count:.1..x-b
	0x0800:  332d 7472 6163 6569 643a 2039 6438 6138  3-traceid:.9d8a8
	0x0810:  3430 3561 3665 6162 6539 6430 6331 6230  405a6eabe9d0c1b0
	0x0820:  3830 3064 6366 6433 3335 330d 0a78 2d62  800dcfd3353..x-b
	0x0830:  332d 7370 616e 6964 3a20 3063 3162 3038  3-spanid:.0c1b08
	0x0840:  3030 6463 6664 3333 3533 0d0a 782d 6233  00dcfd3353..x-b3
	0x0850:  2d73 616d 706c 6564 3a20 300d 0a0d 0a    -sampled:.0....
15:14:48.629733 IP 10-244-0-103.secrets-store.secrets.svc.cluster.local.http-alt > rest-test.35228: Flags [.], ack 4155, win 499, options [nop,nop,TS val 275860676 ecr 2668157115], length 0
	0x0000:  da84 1418 1f2c 7e43 cf19 d33d 0800 4500  .....,~C...=..E.
	0x0010:  0034 da58 4000 3f06 4b17 0af4 0067 0af4  .4.X@.?.K....g..
	0x0020:  0006 1f90 899c 1cf1 b891 4f1d e374 8010  ..........O..t..
	0x0030:  01f3 167b 0000 0101 080a 1071 4cc4 9f08  ...{.......qL...
	0x0040:  d8bb                                     ..
15:14:48.630862 IP 10-244-0-103.secrets-store.secrets.svc.cluster.local.http-alt > rest-test.35228: Flags [P.], seq 1088:2175, ack 4155, win 501, options [nop,nop,TS val 275860677 ecr 2668157115], length 1087: HTTP: HTTP/1.1 200 OK
	0x0000:  da84 1418 1f2c 7e43 cf19 d33d 0800 4500  .....,~C...=..E.
	0x0010:  0473 da59 4000 3f06 46d7 0af4 0067 0af4  .s.Y@.?.F....g..
	0x0020:  0006 1f90 899c 1cf1 b891 4f1d e374 8018  ..........O..t..
	0x0030:  01f5 1aba 0000 0101 080a 1071 4cc5 9f08  ...........qL...
	0x0040:  d8bb 4854 5450 2f31 2e31 2032 3030 204f  ..HTTP/1.1.200.O
	0x0050:  4b0d 0a64 6174 653a 204d 6f6e 2c20 3330  K..date:.Mon,.30
	0x0060:  204a 616e 2032 3032 3320 3135 3a31 343a  .Jan.2023.15:14:
	0x0070:  3438 2047 4d54 0d0a 636f 6e74 656e 742d  48.GMT..content-
	0x0080:  6c65 6e67 7468 3a20 3533 0d0a 636f 6e74  length:.53..cont
	0x0090:  656e 742d 7479 7065 3a20 7465 7874 2f70  ent-type:.text/p
	0x00a0:  6c61 696e 3b20 6368 6172 7365 743d 7574  lain;.charset=ut
	0x00b0:  662d 380d 0a78 2d65 6e76 6f79 2d75 7073  f-8..x-envoy-ups
	0x00c0:  7472 6561 6d2d 7365 7276 6963 652d 7469  tream-service-ti
	0x00d0:  6d65 3a20 300d 0a78 2d65 6e76 6f79 2d70  me:.0..x-envoy-p
	0x00e0:  6565 722d 6d65 7461 6461 7461 3a20 4369  eer-metadata:.Ci
	0x00f0:  554b 446b 4651 5546 3944 5430 3555 5155  UKDkFQUF9DT05UQU
	0x0100:  6c4f 5256 4a54 4568 4d61 4558 4e6c 5933  lORVJTEhMaEXNlY3
	0x0110:  4a6c 6448 4d74 5932 3975 6447 4670 626d  JldHMtY29udGFpbm
	0x0120:  5679 4368 6f4b 436b 4e4d 5656 4e55 5256  VyChoKCkNMVVNURV
	0x0130:  4a66 5355 5153 4442 6f4b 5333 5669 5a58  JfSUQSDBoKS3ViZX
	0x0140:  4a75 5a58 526c 6377 6f65 4367 784a 546c  JuZXRlcwoeCgxJTl
	0x0150:  4e55 5155 3544 5256 394a 5546 4d53 4468  NUQU5DRV9JUFMSDh
	0x0160:  6f4d 4d54 4175 4d6a 5130 4c6a 4175 4d54  oMMTAuMjQ0LjAuMT
	0x0170:  417a 4368 6b4b 4455 6c54 5645 6c50 5831  AzChkKDUlTVElPX1
	0x0180:  5a46 556c 4e4a 5430 3453 4342 6f47 4d53  ZFUlNJT04SCBoGMS
	0x0190:  3478 4e69 3478 4372 4542 4367 5a4d 5155  4xNi4xCrEBCgZMQU
	0x01a0:  4a46 5446 4d53 7067 4571 6f77 454b 4667  JFTFMSpgEqowEKFg
	0x01b0:  6f44 5958 4277 4567 3861 4458 4e6c 5933  oDYXBwEg8aDXNlY3
	0x01c0:  4a6c 6448 4d74 6333 5276 636d 554b 4a41  JldHMtc3RvcmUKJA
	0x01d0:  6f5a 6332 566a 6458 4a70 6448 6b75 6158  oZc2VjdXJpdHkuaX
	0x01e0:  4e30 6157 3875 6157 3876 6447 787a 5457  N0aW8uaW8vdGxzTW
	0x01f0:  396b 5a52 4948 4767 5670 6333 5270 6277  9kZRIHGgVpc3Rpbw
	0x0200:  6f79 4368 397a 5a58 4a32 6157 4e6c 4
```
**Note: You can see that the payload is in plaintext, and an attacker can take the JWT from there, which is very bad.**

5. Let the sniffer continue listening to packets in that window, and go to the other terminal window, and now delete the peerAuthentication objects, to revive auto mTLS:
```shell
kubectl delete peerauthentications.security.istio.io default -n consuming-test
kubectl delete peerauthentications.security.istio.io default -n secrets
```
6. Run another request from client:
```shell
export TOKEN=$(cat ./jwt/demo.jwt) ; kubectl exec rest-test -n consuming-test sh -- wget http://secrets-store.secrets:8080/client/v1/secret/TOKEN --header 'Authorization: Bearer '$TOKEN'' -S  -O -
```
Output:
```shell
Connecting to secrets-store.secrets:8080 (10.103.98.38:8080)
  HTTP/1.1 200 OK
  date: Mon, 30 Jan 2023 15:23:32 GMT
  content-length: 53
  content-type: text/plain; charset=utf-8
  x-envoy-upstream-service-time: 2
  server: envoy
  connection: close
  
writing to stdout
-                    100% |********************************|    53  0:00:00 ETA
written to stdout
{"secretName":"TOKEN","secretValue":"mysecrettoken"}
```
8. Go to terminal with tcpdump sniffer and looks that the payload and headers are all encrypted now, as expected and desired:
```shell
15:21:26.547143 IP rest-test.41910 > 10-244-0-103.secrets-store.secrets.svc.cluster.local.http-alt: Flags [P.], seq 2477:4576, ack 2165, win 502, options [nop,nop,TS val 2668555032 ecr 276258593], length 2099: HTTP
	0x0000:  7e43 cf19 d33d da84 1418 1f2c 0800 4500  ~C...=.....,..E.
	0x0010:  0867 e166 4000 4006 3ad6 0af4 0006 0af4  .g.f@.@.:.......
	0x0020:  0067 a3b6 1f90 ed70 40aa 30ce f9d7 8018  .g.....p@.0.....
	0x0030:  01f6 1eae 0000 0101 080a 9f0e eb18 1077  ...............w
	0x0040:  5f21 1703 0308 2e43 5fe9 ec20 a12f be09  _!.....C_..../..
	0x0050:  dbb7 2172 9c58 e6f1 3833 b5f0 7b20 ece5  ..!r.X..83..{...
	0x0060:  4894 c99c 56cd cde3 4485 7dc3 63e0 6cef  H...V...D.}.c.l.
	0x0070:  5354 b375 5f90 40c5 6131 a85f 9a8b c786  ST.u_.@.a1._....
	0x0080:  a75d 7e17 e351 6a06 0006 319c ac86 227a  .]~..Qj...1..."z
	0x0090:  ea7b 1680 baec 4270 0507 eebe b547 3a10  .{....Bp.....G:.
	0x00a0:  9e94 f185 cf10 4900 b9ef fb98 7589 2820  ......I.....u.(.
	0x00b0:  2bec 1cf9 728a 6729 fd79 abcc 05d5 9de1  +...r.g).y......
	0x00c0:  8bf7 2e05 3b0a 8482 a824 47ce 695c 58f5  ....;....$G.i\X.
	0x00d0:  8166 f9e3 105d 8ae5 1f6e 27c7 3d89 b3b5  .f...]...n'.=...
	0x00e0:  e2dd 84e4 f9c8 f457 987c 495b 06e4 32a9  .......W.|I[..2.
	0x00f0:  214d 74f5 3582 4a2d aa91 ccd2 fa9e e456  !Mt.5.J-.......V
	0x0100:  4ab2 6830 ff03 e37c c743 8fed 365c f888  J.h0...|.C..6\..
	0x0110:  7e26 d106 c685 67d2 f236 192a 01b9 a94a  ~&....g..6.*...J
	0x0120:  fc42 55bb 2b17 a254 d731 f6f7 7642 d3dc  .BU.+..T.1..vB..
	0x0130:  f37c 2a04 82a9 3991 f597 46c6 dc45 a390  .|*...9...F..E..
	0x0140:  828a aa74 4ead 422a 7412 7060 ac97 4246  ...tN.B*t.p`..BF
	0x0150:  10b0 d110 c0a1 9adf 09d3 2058 3311 ed81  ...........X3...
	0x0160:  a7eb 3c47 f0e4 4f73 a359 5df1 2bd1 bfe2  ..<G..Os.Y].+...
	0x0170:  37b2 f212 bbaf 8657 1c5d dfd2 2159 a0e4  7......W.]..!Y..
	0x0180:  ede0 0a19 5299 57aa ffb2 a315 701f 3180  ....R.W.....p.1.
	0x0190:  a2e8 9bf4 43fb d741 fe79 03db 9601 b293  ....C..A.y......
	0x01a0:  624a dae1 a4b2 e1f9 2ae9 2b0a c79b 4970  bJ......*.+...Ip
	0x01b0:  5bb5 35ad d882 cd9f 8602 4dd0 38f6 d70a  [.5.......M.8...
	0x01c0:  36dd 9311 39fc 22df 8a76 ddef 15db 86d6  6...9."..v......
	0x01d0:  6e6d 9633 c904 df51 3ce1 822d cac6 05e7  nm.3...Q<..-....
	0x01e0:  6106 54a8 d47c 30eb 914a d3c3 69be 5ef0  a.T..|0..J..i.^.
	0x01f0:  c5f3 96f2 5383 e291 ed0a 43bf 4cb6 e26e  ....S.....C.L..n
	0x0200:  68d4 c133 3eda 520b c0ef 7167 a5a8 be02  h..3>.R...qg....
	0x0210:  038e 7a77 119f a45d 140c b469 6a2f 8c04  ..zw...]...ij/..
	0x0220:  ee08 bc80 f868 c6b5 66fa 8caf 2f8b f5fa  .....h..f.../...
	0x0230:  fc0b f2a4 b0f8 e881 81b0 8b8a 5830 ed80  ............X0..
	0x0240:  48fd 28c0 556d 67f5 a23a d9c9 38ba bece  H.(.Umg..:..8...
	0x0250:  d85d 0e17 a651 e013 f7d8 5fcd 1153 f547  .]...Q...._..S.G
	0x0260:  7076 8509 2839 a1db 21e9 092d a996 92fc  pv..(9..!..-....
	0x0270:  6096 acf4 8d59 98cd 9a4c e824 af5e 6c7e  `....Y...L.$.^l~
	0x0280:  fa1e 7fed ed21 eee3 f5fa 34bb edc8 f359  .....!....4....Y
	0x0290:  cf4a 659b 2de3 de0d 4e13 f076 e829 2446  .Je.-...N..v.)$F
	0x02a0:  ba91 3fa8 d736 0de3 6209 fe17 426b 7a45  ..?..6..b...BkzE
	0x02b0:  2bde 9eca c48a 7466 bd70 57f6 4165 34d4  +.....tf.pW.Ae4.
	0x02c0:  a411 c34a 2586 c08a 21ed de28 268f c334  ...J%...!..(&..4
	0x02d0:  9d86 6a76 564c 3c2f 38de f155 7c36 85ba  ..jvVL</8..U|6..
	0x02e0:  f5a0 2e62 d02d 50fb c1e4 9c9e e3be 77bb  ...b.-P.......w.
	0x02f0:  3271 d6f8 e536 2e8c 78a4 065d ec13 2cbb  2q...6..x..]..,.
	0x0300:  6366 4d7f 6b3c 98a1 1c3b d9a5 fd0d 3178  cfM.k<...;....1x
	0x0310:  328d 1848 602a 3ba7 6ae4 42cc 9536 4a56  2..H`*;.j.B..6JV
	0x0320:  dd86 995d 0bc2 babe 919f 64ca 004c 4866  ...]......d..LHf
	0x0330:  390d 2907 77e1 ca19 8fb9 5797 e928 c1ad  9.).w.....W..(..
	0x0340:  4998 4e10 86f4 0255 f62b 06b2 a17d 59b9  I.N....U.+...}Y.
	0x0350:  8faf 3d93 ea82 0773 1b61 f046 dce5 b715  ..=....s.a.F....
	0x0360:  e9b4 6b24 1ae9 06a0 529b c897 81a9 69ea  ..k$....R.....i.
	0x0370:  7060 d8cb cf39 ee05 b5bd 0537 d187 a365  p`...9.....7...e
	0x0380:  ce04 5c1c d68c 45e1 18f2 1c75 a7d5 2192  ..\...E....u..!.
	0x0390:  ae51 8be2 a59c d225 b13d 3004 a6e9 4203  .Q.....%.=0...B.
	0x03a0:  23df a067 59db e0e1 2539 98f9 01cc 31ac  #..gY...%9....1.
	0x03b0:  0967 9e95 e9db 6499 fef7 9ef2 13d3 2f57  .g....d......./W
	0x03c0:  d955 a688 166e 77c6 c0e0 858b d2cc 1eb4  .U...nw.........
	0x03d0:  1a27 41e8 14a2 0a76 6f07 2914 2beb f66e  .'A....vo.).+..n
	0x03e0:  95a6 3f04 75f1 7505 e01c 32f7 ff22 2599  ..?.u.u...2.."%.
	0x03f0:  1748 d221 859f 31aa a773 2b0b dd0d 014a  .H.!..1..s+....J
	0x0400:  f392 5907 ce78 8bf4 fc8f c401 238c a4cb  ..Y..x......#...
	0x0410:  fb40 020c b263 f0af 5f4c 0f41 5108 1f83  .@...c.._L.AQ...
	0x0420:  08da 6435 5775 3846 8a42 cdbf 5800 5230  ..d5Wu8F.B..X.R0
	0x0430:  2d46 be36 3aa4 1ead 515e 3486 8eb4 08e8  -F.6:...Q^4.....
	0x0440:  17b6 edad ff19 e6a5 22e5 9226 c051 e051  ........"..&.Q.Q
	0x0450:  9de0 1d75 a368 b4a6 d48a 40fc 3b6a 841e  ...u.h....@.;j..
	0x0460:  4aab a72f 9b03 d105 8456 e55a 99b6 76c9  J../.....V.Z..v.
	0x0470:  6a29 14f4 8051 1722 3a34 747e dd7a bbd7  j)...Q.":4t~.z..
	0x0480:  8ee6 7c67 eb0c e322 1b43 6ba9 bbce 066d  ..|g...".Ck....m
	0x0490:  3058 fa80 eb1a 0efe 447f 9ab2 ace0 22c6  0X......D.....".
	0x04a0:  8dc5 9114 2739 2013 fc5f 03aa 67bd 03ec  ....'9..._..g...
	0x04b0:  1dc1 34f4 9dac 8e2b cbf0 2f59 8833 4836  ..4....+../Y.3H6
	0x04c0:  3734 6314 6b47 3fb9 f045 0e5e 22ed 3820  74c.kG?..E.^".8.
	0x04d0:  5f46 3a48 4114 7219 d433 fade f2b4 d29d  _F:HA.r..3......
	0x04e0:  2f20 3b38 dce5 dca4 5923 5e61 b1ca c317  /.;8....Y#^a....
	0x04f0:  c745 4e62 110f ba5e aa4f ae54 d9df e071  .ENb...^.O.T...q
	0x0500:  569b 1e29 a335 72f7 1f1a 3cdb 8ac4 f1ac  V..).5r...<.....
	0x0510:  3297 f4fc ffc2 fb8a 5038 d06b cfcb 4f74  2.......P8.k..Ot
	0x0520:  26d3 7319 8ee5 ca4e 8b56 feb2 fa40 cec6  &.s....N.V...@..
	0x0530:  8b6d c4da 2bc1 5312 141a e218 c52e 551d  .m..+.S.......U.
	0x0540:  5219 ed2b f78a 656b 6d05 7d6f 8e35 e00f  R..+..ekm.}o.5..
	0x0550:  8602 ad58 3c00 7636 a49f b23d 2905 f388  ...X<.v6...=)...
	0x0560:  a3dc ec53 ca02 f86c 1469 81bc 9d12 6a23  ...S...l.i....j#
	0x0570:  5324 b28a c4f8 41a4 3f74 f8ff d65a 7d3f  S$....A.?t...Z}?
	0x0580:  9b60 3cf3 b1d2 d078 21cf 9c48 809f fdd1  .`<....x!..H....
	0x0590:  98c3 8454 37a0 efbb b4d2 500a dbff d069  ...T7.....P....i
	0x05a0:  6219 218e b128 93d2 9e97 f2df 89ff 6b44  b.!..(........kD
	0x05b0:  aba1 c32c 154e 48a8 fac7 4f1f 5a50 250c  ...,.NH...O.ZP%.
	0x05c0:  0249 9ab5 be78 9f82 cc06 6093 b074 0569  .I...x....`..t.i
	0x05d0:  1b43 8b19 9700 14d3 b22a c44f a2a3 a0fa  .C.......*.O....
	0x05e0:  138e 5f4b 7462 1c21 f9e0 4b3a 55a4 13b9  .._Ktb.!..K:U...
	0x05f0:  a332 2612 ce6f 2444 985e 418c 58b5 7a70  .2&..o$D.^A.X.zp
	0x0600:  344d 4467 7e36 04cc 151f 25a5 4aef c252  4MDg~6....%.J..R
	0x0610:  322c 1ec3 7ff4 ff8b 83c9 42e7 2819 1a0b  2,........B.(...
	0x0620:  6e3c 64c7 c93f 9668 df93 2f56 879e 56c6  n<d..?.h../V..V.
	0x0630:  3146 c6dc a6b1 aed4 c6a5 470d 98c9 225e  1F........G..."^
	0x0640:  2ca9 3022 c4f6 6c43 b0fe 3659 236d 42a5  ,.0"..lC..6Y#mB.
	0x0650:  f516 2f3e e83f b748 ad06 3da5 28b4 4441  ../>.?.H..=.(.DA
	0x0660:  8280 d636 bbc4 68b7 fbb2 ee73 0cb9 9fd7  ...6..h....s....
	0x0670:  9a6a e810 5d23 5d2a 7fec 868a 62ba f414  .j..]#]*....b...
	0x0680:  1349 f546 b80c aafb a14b e733 4b73 7b72  .I.F.....K.3Ks{r
	0x0690:  4a1b 9180 535b 1d06 daf6 2f17 d80e f169  J...S[..../....i
	0x06a0:  020d 92d3 a091 b261 97a6 5bce f97b 2260  .......a..[..{"`
	0x06b0:  1681 8b61 5f2b 6eff 636b 0202 4fdd c31a  ...a_+n.ck..O...
	0x06c0:  709d caaa ed5e 0ec0 011f 9e79 34eb 43b4  p....^.....y4.C.
	0x06d0:  1b8c 2e7e d0fc d438 3c5d 1839 397c fd88  ...~...8<].99|..
	0x06e0:  02af a74a 15ed 4e79 9041 3767 ace5 f078  ...J..Ny.A7g...x
	0x06f0:  eb17 4726 dc7d 4dc9 d037 f2cb 3c0f bdbc  ..G&.}M..7..<...
	0x0700:  903b 0286 05ad 3400 1c6b 194e d545 fb43  .;....4..k.N.E.C
	0x0710:  f925 bbc5 32b3 4a91 d45e 2eab 7371 8444  .%..2.J..^..sq.D
	0x0720:  7143 cc1a 594d 4fb8 d46d eee9 c7b3 a105  qC..YMO..m......
	0x0730:  abb2 ea39 0525 a170 da0a a355 a76d 9867  ...9.%.p...U.m.g
	0x0740:  7280 5021 33cf c0c8 cfa6 fb0d 84da 48a8  r.P!3.........H.
	0x0750:  7cd8 53b0 91a1 58b2 c979 7dce ef2f 4733  |.S...X..y}../G3
	0x0760:  1fdf f113 e23f 0a47 566b b208 d6f1 5c62  .....?.GVk....\b
	0x0770:  aa3d 479e 866b 6f01 d2d6 126d 81f4 eca9  .=G..ko....m....
	0x0780:  f367 154f 1ca9 7d06 7e98 5a9f 2d7d 97ac  .g.O..}.~.Z.-}..
	0x0790:  7ba2 291b e4ac 2c83 30c6 72c3 a3eb 4550  {.)...,.0.r...EP
	0x07a0:  e6e3 808d 5ed2 572b 1954 1d92 f015 cf42  ....^.W+.T.....B
	0x07b0:  f6d1 32c3 d4d0 89b4 0462 892a 1dd7 c00d  ..2......b.*....
	0x07c0:  3264 7844 6cd7 60bb 5fd8 7386 5937 8779  2dxDl.`._.s.Y7.y
	0x07d0:  90e7 9057 2b23 adf7 2162 4493 f556 b216  ...W+#..!bD..V..
	0x07e0:  29e0 51e9 b22b 1c40 ca5e 14c6 30f9 03e9  ).Q..+.@.^..0...
	0x07f0:  a67f a82b 47cc d1fb 13d8 503a 3727 5bb6  ...+G.....P:7'[.
	0x0800:  6a93 4abd 0605 c8a8 5c59 41bd 389a b15d  j.J.....\YA.8..]
	0x0810:  1268 c02e c9eb b419 6a35 1137 98a0 0f56  .h......j5.7...V
	0x0820:  5cd2 12ef cb86 cb97 fbd4 9ff5 7cfe 1594  \...........|...
	0x0830:  c2dc 3f8d dbba f470 2b52 e67c 0a51 00ce  ..?....p+R.|.Q..
	0x0840:  8943 3f6e 8efe 6d09 0ae3 0c31 e549 f770  .C?n..m....1.I.p
	0x0850:  6c74 f6ef c456 9743 3a2e 6be4 732d c1ea  lt...V.C:.k.s-..
	0x0860:  ab79 383d 9ad7 a0a7 21ba 5410 b07d 5b41  .y8=....!.T..}[A
	0x0870:  7383 3f13 94                             s.?..
15:21:26.547152 IP 10-244-0-103.secrets-store.secrets.svc.cluster.local.http-alt > rest-test.41910: Flags [.], ack 4576, win 499, options [nop,nop,TS val 276258593 ecr 2668555032], length 0
	0x0000:  da84 1418 1f2c 7e43 cf19 d33d 0800 4500  .....,~C...=..E.
	0x0010:  0034 ff5c 4000 3f06 2613 0af4 0067 0af4  .4.\@.?.&....g..
	0x0020:  0006 1f90 a3b6 30ce f9d7 ed70 48dd 8010  ......0....pH...
	0x0030:  01f3 167b 0000 0101 080a 1077 5f21 9f0e  ...{.......w_!..
	0x0040:  eb18                                     ..
15:21:26.548275 IP 10-244-0-103.secrets-store.secrets.svc.cluster.local.http-alt > rest-test.41910: Flags [P.], seq 2165:7020, ack 4576, win 501, options [nop,nop,TS val 276258594 ecr 2668555032], length 4855: HTTP
	0x0000:  da84 1418 1f2c 7e43 cf19 d33d 0800 4500  .....,~C...=..E.
	0x0010:  132b ff5d 4000 3f06 131b 0af4 0067 0af4  .+.]@.?......g..
	0x0020:  0006 1f90 a3b6 30ce f9d7 ed70 48dd 8018  ......0....pH...
	0x0030:  01f5 2972 0000 0101 080a 1077 5f22 9f0e  ..)r.......w_"..
	0x0040:  eb18 1703 030e 9d57 b0ba 2b48 c85a 2eb4  .......W..+H.Z..
	0x0050:  6bd0 8d59 4bc8 ed4b 007a 9da3 9bb8 105b  k..YK..K.z.....[
	0x0060:  ef9b eca1 9239 ce7f 9434 56d4 19d3 aa1e  .....9...4V.....
	0x0070:  20c4 ec10 0837 16f0 7041 e2a4 e2c4 4900  .....7..pA....I.
	0x0080:  e39a e495 93af 61ca c227 744b 16af 2d5b  ......a..'tK..-[
	0x0090:  8af1 eeba 773f c26f c58c 9a2c 7c9a 2aaa  ....w?.o...,|.*.
	0x00a0:  c0ff 51ea 75a7 4bfb 974e a45a 40d4 7f28  ..Q.u.K..N.Z@..(
	0x00b0:  5ba2 5712 cc77 2987 e165 1dfb 1c81 372e  [.W..w)..e....7.
	0x00c0:  9f70 af75 107c 0eea 74de f21a 4cd9 55e3  .p.u.|..t...L.U.
	0x00d0:  030e 5698 7f1a 35b0 93b3 17e5 3077 798e  ..V...5.....0wy.
	0x00e0:  5e8f 2e47 04dd e1a3 e2d9 aad1 27c7 abef  ^..G........'...
	0x00f0:  0da1 71ef 2f0c 71a5 0241 4d5a 9b32 bdcd  ..q./.q..AMZ.2..
	0x0100:  79f4 f81d 9d33 7f84 0cd8 bbe4 cae2 6502  y....3........e.
	0x0110:  63a2 4de7 39c7 e0f3 f5da c3f6 5aa6 f93d  c.M.9.......Z..=
	0x0120:  2756 2556 147d eee2 3d95 dc47 1092 e79e  'V%V.}..=..G....
	0x0130:  b1c1 9e1f 5142 8fe5 a68e dfdb 6b17 1d60  ....QB......k..`
	0x0140:  294d 735d d818 c586 edbd 21b8 1c5f d18d  )Ms]......!.._..
	0x0150:  a865 6bb2 ec53 ebc2 72ac 9c5b 5956 448a  .ek..S..r..[YVD.
	0x0160:  7e95 7b1d d46d 6fab caae b4f6 ca2f f748  ~.{..mo....../.H
	0x0170:  8518 4d9f 41a1 3e0e 9ca8 651a 8786 af93  ..M.A.>...e.....
	0x0180:  fe02 796b bc39 f50a ecc8 50ea 9dc3 8761  ..yk.9....P....a
	0x0190:  9620 559c e24e b3a2 ce29 58c7 c380 072e  ..U..N...)X.....
	0x01a0:  8573 8298 d9bc e5ab 16fa 4f6f 7a05 942f  .s........Ooz../
	0x01b0:  17b4 cfca 40f4 96cc 0f7c 100c b462 288b  ....@....|...b(.
	0x01c0:  e75e 868d 81ae 89a7 a618 4fe2 62e5 1431  .^........O.b..1
	0x01d0:  782e 6578 e18b f648 e67e 97ba f275 5116  x.ex...H.~...uQ.
	0x01e0:  8cf5 ecb8 fa10 1ed8 1ff1 3d59 04da af6b  ..........=Y...k
	0x01f0:  4c7b 6903 fbe2 b7d5 a266 bc2f ece3 56af  L{i......f./..V.
	0x0200:  7c3b c684 c0c0 7b37 664c 4d5c 653d 4b14  |;....{7fLM\e=K.
	0x0210:  ee5a 0f9e bd2f 29c1 f6c3 4f9a ddcd 7611  .Z.../)...O...v.
	0x0220:  3842 0c33 221f 58a2 7476 5cf4 87be 7031  8B.3".X.tv\...p1
	0x0230:  1eaa c075 7b18 7832 5c7f 10bd 6fb8 dd88  ...u{.x2\...o...
	0x0240:  38a7 6dac 6698 1c31 79af 77c6 a8cd 4625  8.m.f..1y.w...F%
	0x0250:  0bb7 1588 1315 4732 bdea 3f3a 73c3 5076  ......G2..?:s.Pv
	0x0260:  8427 362c 193d aee5 6698 7f57 68ad 9a60  .'6,.=..f..Wh..`
	0x0270:  f2f3 f3ce 2b8d 9f0f eb4b e46e 0fed 6852  ....+....K.n..hR
	0x0280:  e6e3 0dbd 401f 632c 3b8b f7cc cbea 5c5d  ....@.c,;.....\]
	0x0290:  2f08 116b a60f ac39 2b80 7a15 e1cd b2eb  /..k...9+.z.....
	0x02a0:  ba6b bee5 8bc5 6315 bc58 520c bf92 92a7  .k....c..XR.....
	0x02b0:  94be 9b0a ed94 fa42 2c54 5994 e52c 6cdb  .......B,TY..,l.
	0x02c0:  f35e 4375 aea4 e18c ab40 0d64 d71d d0d3  .^Cu.....@.d....
	0x02d0:  d1b3 a1e2 9170 d229 c808 d643 94d1 ccd2  .....p.)...C....
	0x02e0:  d785 c842 0afd 0933 61e0 ec6e 0dd5 2bfc  ...B...3a..n..+.
	0x02f0:  771f a163 bb4f 6b65 22b8 c30f 1bb3 3df0  w..c.Oke".....=.
	0x0300:  008e c8bb 4aaf faeb e9f2 12d8 e1d3 9a7c  ....J..........|
	0x0310:  6847 3b4e c8bc b001 8cc9 fd96 2de7 eab6  hG;N........-...
	0x0320:  9630 d703 d1b8 6fcb 58ff 1bfb 8531 8924  .0....o.X....1.$
	0x0330:  371c 53c7 6a29 f7bb 6cd4 b366 1aca 878f  7.S.j)..l..f....
	0x0340:  5f26 60c3 28fd c664 1a1b 190e b00f 5885  _&`.(..d......X.
	0x0350:  2dd6 a25e 9bc3 7a1b 4fed 3293 4c1a f22e  -..^..z.O.2.L...
	0x0360:  142f 6d9f dedf 1795 e4b5 ca46 c9b1 b61f  ./m........F....
	0x0370:  3690 8556 f24e 9d9c 4204 ddb6 1b08 5070  6..V.N..B.....Pp
	0x0380:  ba7e 7dd7 bb82 b856 3602 bf21 2bca 72a0  .~}....V6..!+.r.
	0x0390:  97a0 f59e 0196 284c b506 19f8 d8f6 d166  ......(L.......f
	0x03a0:  ca17 9d14 0a3a 73f2 52b3 c91b 68a7 947b  .....:s.R...h..{
	0x03b0:  f3a6 46b2 455e c147 bab3 1961 7101 16ff  ..F.E^.G...aq...
	0x03c0:  b138 5ebe 0e57 b923 848e bc26 4181 d3d6  .8^..W.#...&A...
	0x03d0:  8b08 a133 a956 22e4 1009 fb9a 8897 61b6  ...3.V".......a.
	0x03e0:  1153 1218 18e9 9562 7093 ffff 9a35 729e  .S.....bp....5r.
	0x03f0:  d404 9da7 c8fb 265a fa21 494d 4254 a2f4  ......&Z.!IMBT..
	0x0400:  daf9 40fe 8d02 f63b 38a1 86ff 53aa d083  ..@....;8...S...
	0x0410:  9fbf a384 0e14 6c5c 2e9e f44e 9408 5f70  ......l\...N.._p
	0x0420:  5ab6 d18b 53db ed0f 7967 59cf be7d 5cc5  Z...S...ygY..}\.
	0x0430:  5f50 010e a7a5 7f88 7fee 4425 9ba9 229f  _P........D%..".
	0x0440:  79ea d991 8859 0845 4fa0 d860 c7d9 bff7  y....Y.EO..`....
	0x0450:  103f 3ae2 882a eb7c 3afe 3f8c 5079 4c76  .?:..*.|:.?.PyLv
	0x0460:  ebb2 9c21 395d 5eb0 5946 d93a 9afe 0dd9  ...!9]^.YF.:....
	0x0470:  8f5c 4ed8 2565 2aa9 304c 8990 b37a 06ff  .\N.%e*.0L...z..
	0x0480:  4c77 f6dc da5f cdc6 8677 0943 4490 6190  Lw..._...w.CD.a.
	0x0490:  6d94 4522 ddf5 cdc4 dfea ca8f 4199 b5b7  m.E"........A...
	0x04a0:  d1be 5f51 17aa 587b 32c3 2188 126e 2f45  .._Q..X{2.!..n/E
	0x04b0:  7c78 0d07 64cf d291 70a7 64aa 8c75 09f2  |x..d...p.d..u..
	0x04c0:  25ab 5eda 354b e2fd 9f58 d3d0 d346 e34a  %.^.5K...X...F.J
	0x04d0:  5943 24bb 52d7 9f4e 0074 008c 2e1b 6b0b  YC$.R..N.t....k.
	0x04e0:  c3ed 5fab d582 f2b7 7526 1aa3 61a7 f2e1  .._.....u&..a...
	0x04f0:  ea3e cc3e 893f d1c6 e388 9d58 12a3 3533  .>.>.?.....X..53
	0x0500:  4e5b 44b4 f693 711e 0e37 76eb fa52 1829  N[D...q..7v..R.)
	0x0510:  67dc 1c3f c2cf 7b74 84ae 05a6 11ed 4476  g..?..{t......Dv
	0x0520:  f202 b76c 0732 c49e 556e a06a 6d20 003a  ...l.2..Un.jm..:
	0x0530:  ae06 a6b2 79c5 32ca 03a7 2d39 d9e0 70d6  ....y.2...-9..p.
	0x0540:  207b 8933 44dd a8ad 7247 8c6a 4d5b 7328  .{.3D...rG.jM[s(
	0x0550:  b4e3 436c a606 11c0 04a4 4fcc d44a 1a7d  ..Cl......O..J.}
	0x0560:  9631 b58e 4187 8031 274c 91d9 047e 4d0b  .1..A..1'L...~M.
	0x0570:  2fd1 8b3a 9280 a4b3 e082 16a1 4418 94a5  /..:........D...
	0x0580:  f37c dec0 9454 1228 39d4 857a 152a 7ab7  .|...T.(9..z.*z.
	0x0590:  ca88 39cb feeb 47da 9a70 c4ad 867e 51a9  ..9...G..p...~Q.
	0x05a0:  8b0f 362f 3890 afeb 1858 c08b 1954 d90c  ..6/8....X...T..
	0x05b0:  f807 7ee2 f2ce d52f 69ab 9a43 9e77 2aa8  ..~..../i..C.w*.
	0x05c0:  4d5f 419d d6ea 0bb6 e22e 6b56 a0d6 4dd6  M_A.......kV..M.
	0x05d0:  ed32 3a8e 9a86 0767 2ca5 4444 1d2d 130b  .2:....g,.DD.-..
	0x05e0:  0ff5 8932 ee93 88ff 6cac cce2 15e3 e606  ...2....l.......
	0x05f0:  b71d b0e2 ca10 64c9 88d0 086b 092f bb77  ......d....k./.w
	0x0600:  19e6 0c88 b4b1 e1a3 cdc2 a28d 5331 f45f  ............S1._
	0x0610:  11be b5a9 620b 8a65 232c 867e d25c e797  ....b..e#,.~.\..
	0x0620:  aa99 1451 fa6c e165 f102 132a 66dc 5512  ...Q.l.e...*f.U.
	0x0630:  b152 e48f f326 0029 627b d23d e4a0 9c32  .R...&.)b{.=...2
	0x0640:  529c aac3 9156 7767 77a7 8b6e 03ab 4d92  R....Vwgw..n..M.
	0x0650:  b75e da9d 2149 ee8c 02ea a8da 812e 5df7  .^..!I........].
	0x0660:  7b49 7712 46ce a66f 1939 7904 a3a6 26a2  {Iw.F..o.9y...&.
	0x0670:  6673 9f55 f77d d8a0 a720 c658 3a3b 6b3b  fs.U.}.....X:;k;
	0x0680:  8979 3fe6 bcc2 cbf9 324b 1885 7ee4 8aef  .y?.....2K..~...
	0x0690:  1127 173f 88d2 3758 93d4 3432 d50e d0cd  .'.?..7X..42....
	0x06a0:  a0eb 73d0 682d dda8 b025 ea73 fbf6 2b2e  ..s.h-...%.s..+.
	0x06b0:  e0d8 eed7 1a7b 87b4 4d7d b252 dfb7 8d91  .....{..M}.R....
	0x06c0:  9aef 64e0 0dd8 7d7e e13e 7e0c c06b 8082  ..d...}~.>~..k..
	0x06d0:  f726 31ec 1e7b 477d f2c7 67f4 e3ad d8f9  .&1..{G}..g.....
	0x06e0:  b2a3 7494 8907 96fa f110 080a f9d3 7ccf  ..t...........|.
	0x06f0:  2b2e 1fbe b650 1485 58c3 2acc 7db5 8c0b  +....P..X.*.}...
	0x0700:  d141 6fbb 1036 58e1 95b0 7504 7870 2da8  .Ao..6X...u.xp-.
	0x0710:  fac4 0699 c5f5 dcc4 40d2 90bb 10b0 65fe  ........@.....e.
	0x0720:  33bc 9ac0 6802 1ef9 ece6 3b7e 4ff5 a687  3...h.....;~O...
	0x0730:  3989 93f0 664c 41ee c26a f8c3 13fc c146  9...fLA..j.....F
	0x0740:  1dec 4207 9f72 2e78 9ba0 9a79 6b70 0cc7  ..B..r.x...ykp..
	0x0750:  7ee7 6041 4017 eb78 2405 1e00 d68d ec7a  ~.`A@..x$......z
	0x0760:  9f0b 71fd fe79 137a 31af 0d65 0182 0e7a  ..q..y.z1..e...z
	0x0770:  b083 90f1 9cff 8df3 bf9b 4ea3 1590 0b2d  ..........N....-
	0x0780:  5441 0234 f564 2ab9 d6cd 57ca b1d5 4fe6  TA.4.d*...W...O.
	0x0790:  f134 6949 742f 8814 3efb b5fc 236c a9c7  .4iIt/..>...#l..
	0x07a0:  6f60 37c4 1e67 81a1 cb06 3d57 b7e6 a651  o`7..g....=W...Q
	0x07b0:  eb10 470f 3b3f 15e7 9afd 2c6d 8cd6 99c4  ..G.;?....,m....
	0x07c0:  ee25 922a c730 12f7 9850 1951 241e 1a19  .%.*.0...P.Q$...
	0x07d0:  dc15 1d1f 6d40 3153 cfdd a286 6eaf 3f5b  ....m@1S....n.?[
	0x07e0:  af7b 67c0 b5c1 ab86 a012 de39 bf36 8c7e  .{g........9.6.~
	0x07f0:  a1a8 d929 e81f 4fbf 1abd a037 fd7f 71e0  ...)..O....7..q.
	0x0800:  b650 af8b dbf9 f2ab 1356 91b9 ca60 8813  .P.......V...`..
	0x0810:  89a6 146f cd9c f4ab fc5d de86 b41b 1b1d  ...o.....]......
	0x0820:  ba8c 96cb 5b74 2f32 96e2 57b5 409e 529c  ....[t/2..W.@.R.
	0x0830:  ca49 1c62 ef79 b1a4 b783 dde8 ac6f c71f  .I.b.y.......o..
	0x0840:  3c42 8a04 7362 0f63 f1d0 ef4d d9e6 cdbc  <B..sb.c...M....
	0x0850:  38dd 8176 93ba 4323 e250 a052 edb4 0a9c  8..v..C#.P.R....
	0x0860:  2234 22c4 a09c 282b 4c0b 4291 777b 08b5  "4"...(+L.B.w{..
	0x0870:  e304 af0f 609f ed3e e5f2 97b5 81a7 1a28  ....`..>.......(
	0x0880:  5786 7aa2 16a3 7b81 30ed b970 8f7f 9ebb  W.z...{.0..p....
	0x0890:  b899 8235 01b3 01f3 989f 0678 5edb bcd1  ...5.......x^...
	0x08a0:  8949 19e4 dfe0 32fe cc2a cd4c 22ec f525  .I....2..*.L"..%
	0x08b0:  611a 2f85 4ba9 f189 1607 5dbf 30df 4349  a./.K.....].0.CI
	0x08c0:  cf0a f02e 7aa8 35fb 858a 43c1 4563 5785  ....z.5...C.EcW.
	0x08d0:  bb8e dc85 ac68 3f7a 77dc 8ee2 198e f497  .....h?zw.......
	0x08e0:  c65e 6a7e f4eb 5536 4fc3 a940 796d 312d  .^j~..U6O..@ym1-
	0x08f0:  d48c 4e6f 3b60 3cdd 37af 2d3e de80 1a74  ..No;`<.7.->...t
	0x0900:  46dd 270b f2ee 178f cde3 b39a 4849 e65c  F.'.........HI.\
	0x0910:  b994 2a65 319d 9641 41b3 ec86 cf52 9d9a  ..*e1..AA....R..
	0x0920:  1a91 6125 e938 3812 81d7 0044 19a1 08ad  ..a%.88....D....
	0x0930:  37b2 76dd 4ede 5922 dcb3 3447 42b1 1dc6  7.v.N.Y"..4GB...
	0x0940:  0294 05a6 2de7 b43d 4b36 e86a 5253 6dcc  ....-..=K6.jRSm.
	0x0950:  e2a2 d0b7 0ab9 2cb2 19f0 4eda afeb 7d31  ......,...N...}1
	0x0960:  d250 5939 6002 0f24 c511 ed75 2fbd 1b17  .PY9`..$...u/...
	0x0970:  e039 f407 4877 4ddc ff90 ec0c 886f d069  .9..HwM......o.i
	0x0980:  c65e 0c8f 7ffc 51b1 805d ad28 cbdf 4c85  .^....Q..].(..L.
	0x0990:  c56a 603b 9019 d6da 7c18 df1d c98d 504d  .j`;....|.....PM
	0x09a0:  e86c 09a7 5e64 4d29 ae94 47a9 04c3 ea8d  .l..^dM)..G.....
	0x09b0:  14f2 eef2 e1ae 647e 4098 7454 8095 e050  ......d~@.tT...P
	0x09c0:  39c9 5a62 a73f 816b 303a 8aa5 c5b1 8dad  9.Zb.?.k0:......
	0x09d0:  998f fc8f 7e4f 8e83 8289 8bb3 16eb 7088  ....~O........p.
	0x09e0:  6921 3402 202d 1ef2 431b d532 53a8 3579  i!4..-..C..2S.5y
	0x09f0:  e986 1198 6434 285f 842e a83b 769f f7ee  ....d4(_...;v...
	0x0a00:  ecbd 7d26 4050 e0eb d844 e044 18ef 6962  ..}&@P...D.D..ib
	0x0a10:  83ab 1e7e 3e20 ce72 d1b4 7106 a162 52e8  ...~>..r..q..bR.
	0x0a20:  2c5a aef1 24bb 39bd 318d e401 3cfa 94f3  ,Z..$.9.1...<...
	0x0a30:  35be bec3 200c 16bb 565b bee8 fcec 3cc1  5.......V[....<.
	0x0a40:  c001 434b 0980 2b6e f3a7 3156 3381 f407  ..CK..+n..1V3...
	0x0a50:  9082 ce5d d1c3 9bfe 13e9 a5b5 f5e5 c919  ...]............
	0x0a60:  06eb 093d 4f11 d9e7 9a3d bf17 1a19 b0e1  ...=O....=......
	0x0a70:  01ce a32d 6e35 4dd7 acdf 3976 3ed6 6d72  ...-n5M...9v>.mr
	0x0a80:  ef92 6733 f920 2669 ec33 5af8 d7cb d06b  ..g3..&i.3Z....k
	0x0a90:  2ba5 ad5e e494 a280 0164 ed3b 512c 6567  +..^.....d.;Q,eg
	0x0aa0:  f1d2 85ba a729 00e5 f709 879f 8a11 fb72  .....).........r
	0x0ab0:  70ee 15e1 fdda 742c 3540 dd3e a721 e351  p.....t,5@.>.!.Q
	0x0ac0:  63b5 e9cf 1040 e77a 35e4 de79 559d ef98  c....@.z5..yU...
	0x0ad0:  0307 60af b656 970d f25c dcce 576a 4901  ..`..V...\..WjI.
	0x0ae0:  e7d6 aaa3 fd75 2d31 bb90 2652 27d8 a21c  .....u-1..&R'...
	0x0af0:  9065 e4f6 9cb8 0a95 48e7 3ff8 7965 4d75  .e......H.?.yeMu
	0x0b00:  2db7 99b0 3d9e b8a3 abde b848 aa03 2921  -...=......H..)!
	0x0b10:  d80f 79c2 8faf 3021 4a53 ac9f e195 fb80  ..y...0!JS......
	0x0b20:  b2eb 4727 7686 b02a b531 922f 109d ce2e  ..G'v..*.1./....
	0x0b30:  c03a 9db4 acf4 f805 03b4 9a55 3019 b120  .:.........U0...
	0x0b40:  7e2a 46eb 250e 1204 29b7 d602 1534 e23e  ~*F.%...)....4.>
	0x0b50:  fc89 b9d3 501b 934e 136c 6b83 a200 1cc7  ....P..N.lk.....
	0x0b60:  90ad b959 5b42 ecb2 b7f8 532d c9c8 f21f  ...Y[B....S-....
	0x0b70:  d5e4 7e98 b8d2 2231 7e6a a829 2f4e 2a1c  ..~..."1~j.)/N*.
	0x0b80:  2a93 7d35 330d f3bf 5c0a ca76 0a5c 53ea  *.}53...\..v.\S.
	0x0b90:  e54b 700d 145d 0ca4 346e a95b 49a7 1f94  .Kp..]..4n.[I...
	0x0ba0:  6f72 bbf2 3831 5b65 8c61 127a f2b7 6680  or..81[e.a.z..f.
	0x0bb0:  61a5 4201 73de 59d6 fc41 5b8a b47a c28d  a.B.s.Y..A[..z..
	0x0bc0:  3caa abd9 4948 df94 bb9d 651c ed08 4704  <...IH....e...G.
	0x0bd0:  52ea 9243 b073 685d 648d 7adc e65b 4620  R..C.sh]d.z..[F.
	0x0be0:  6c1b 3919 38e7 a34f 740a fc3e e084 3899  l.9.8..Ot..>..8.
	0x0bf0:  e75e 4e3e 0f2e 3c1c cf77 f7c3 ac80 01c5  .^N>..<..w......
	0x0c00:  3bd0 9d33 33e4 12dc 536a 147a 0ed1 bb43  ;..33...Sj.z...C
	0x0c10:  aab9 11b2 86cb 6697 a1a8 96e7 f4d8 df59  ......f........Y
	0x0c20:  4e35 379a d1d8 35d4 90de 8cf6 f81f 5c84  N57...5.......\.
	0x0c30:  61d2 514b 79d1 2928 3daa 7cfa fe3c 9b6b  a.QKy.)(=.|..<.k
	0x0c40:  99cf 57e4 7f0b 8092 cc90 a282 ef59 b74a  ..W..........Y.J
	0x0c50:  563a 9595 0b0d 5440 ac43 5df7 0895 74f1  V:....T@.C]...t.
	0x0c60:  8e1f 8b33 6d68 e42c db90 1bad 981f 9457  ...3mh.,.......W
	0x0c70:  fff8 3b16 6e2d d526 dbed ac6b 8039 6677  ..;.n-.&...k.9fw
	0x0c80:  83b3 beb3 3e8c c853 2bbb e52c 8827 4b78  ....>..S+..,.'Kx
	0x0c90:  8974 8b95 b3f5 7bc2 3108 0a4b 9440 b9ed  .t....{.1..K.@..
	0x0ca0:  8c9b dc63 1ef4 e44f 647d 4a8b 7f9d 0dcb  ...c...Od}J.....
	0x0cb0:  b52d 1b8f 378a 9e89 3877 97e0 912f bc42  .-..7...8w.../.B
	0x0cc0:  3a5d 4b89 d072 f0b0 f0a5 22b5 e8b6 1cac  :]K..r....".....
	0x0cd0:  e870 b588 38eb 695c 102d 3a94 7f5b 3a68  .p..8.i\.-:..[:h
	0x0ce0:  32be 843a 35a7 24f4 2569 2011 d218 6b79  2..:5.$.%i....ky
	0x0cf0:  4bc4 4a2d 6247 0ab3 ee33 2ff2 c4a5 17a6  K.J-bG...3/.....
	0x0d00:  d6c6 3568 b8ad 0906 d54d 65a9 35be b085  ..5h.....Me.5...
	0x0d10:  b2e2 8dd4 439f 9d00 d8a4 6c56 b0b7 d4a2  ....C.....lV....
	0x0d20:  b08d fe92 08d0 8466 9738 aeb9 58bc 1375  .......f.8..X..u
	0x0d30:  e317 4dcf 5e1d 97fa e014 cf94 a0a9 4ad1  ..M.^.........J.
	0x0d40:  157d 9a20 2c6d 0d3b c52d 8c5d d337 0fc5  .}..,m.;.-.].7..
	0x0d50:  f9fa 1561 e386 07a1 3bd7 de50 ffe1 6c38  ...a....;..P..l8
	0x0d60:  a488 6662 0e91 6448 4733 a715 b874 e9d6  ..fb..dHG3...t..
	0x0d70:  9352 246f f68a c5ee 8836 9606 be0c 0d0e  .R$o.....6......
	0x0d80:  142e 03ab bcf9 8ed3 8d83 3c27 616d ba9c  ..........<'am..
	0x0d90:  5170 8cfd b46f fa73 7c65 5722 9fc4 7316  Qp...o.s|eW"..s.
	0x0da0:  add5 c0f8 90a0 a703 ee04 a69c bc17 402e  ..............@.
	0x0db0:  35c9 2602 22ca 7b45 abbd 8aee fb33 133f  5.&.".{E.....3.?
	0x0dc0:  3105 802a be66 1da3 28d7 be26 2e2e f910  1..*.f..(..&....
	0x0dd0:  d930 3362 ab18 383a c647 bae5 1baf e79a  .03b..8:.G......
	0x0de0:  018c 122b 1110 c4e1 d8ae 4d52 3aca c1d8  ...+......MR:...
	0x0df0:  f9f4 2d44 d12c 66a7 5cc4 edba d81a a2b7  ..-D.,f.\.......
	0x0e00:  07ba 38f0 c92f ea51 8454 7ba0 2e49 d605  ..8../.Q.T{..I..
	0x0e10:  7ec8 d47d b8c2 30b0 abbc 1500 4910 e08e  ~..}..0.....I...
	0x0e20:  18ad 0f4e e056 e9f2 d614 0c1c 3e3e 2d4e  ...N.V......>>-N
	0x0e30:  cfba 6360 72e5 973b 3b4d 55f0 632a d813  ..c`r..;;MU.c*..
	0x0e40:  4310 e53a 87ec faea 5cf9 c012 1189 f216  C..:....\.......
	0x0e50:  84f9 ac16 fa55 ead3 c418 6d13 ae11 bc8c  .....U....m.....
	0x0e60:  27b8 37d5 0f19 1f34 bc6f 5883 17e9 0ecb  '.7....4.oX.....
	0x0e70:  a3bf 23ff a737 0006 e3b3 3171 6455 bf39  ..#..7....1qdU.9
	0x0e80:  b4b0 b85a 0e5d bd27 ec73 cbd4 24a7 d7da  ...Z.].'.s..$...
	0x0e90:  e156 024c 6a2f 53b0 4b49 3e35 1126 d02c  .V.Lj/S.KI>5.&.,
	0x0ea0:  8ad8 48b6 3b85 50db d81e 49de d73c a1f6  ..H.;.P...I..<..
	0x0eb0:  f5c5 8a19 7f53 df0b 4353 d472 5439 dade  .....S..CS.rT9..
	0x0ec0:  1eb4 1f4f 6939 bcec e21b 01da d315 ab41  ...Oi9.........A
	0x0ed0:  86c0 21ec 4559 54d7 7aa6 e5f4 9d01 1eb7  ..!.EYT.z.......
	0x0ee0:  a7e6 f347 1703 0304 5033 8815 78af d9ff  ...G....P3..x...
	0x0ef0:  02cf c064 1495 fd90 6f73 8fbb 004d da1d  ...d....os...M..
	0x0f00:  f4e3 f9b7 fb20 b689 9420 6351 ee18 3425  ..........cQ..4%
	0x0f10:  1127 2382 c0ac 578c ec9a d644 a7ab 98fb  .'#...W....D....
	0x0f20:  5093 1116 ca14 2c4b 14ae 6937 22aa ef55  P.....,K..i7"..U
	0x0f30:  ec18 dd2d 2332 ade3 a9ee 3ed9 7004 ebb9  ...-#2....>.p...
	0x0f40:  15ad 45b1 c0f9 898b e385 cbef 1eb2 28be  ..E...........(.
	0x0f50:  f952 4d44 f597 de0b 4d85 ade5 d420 7a30  .RMD....M.....z0
	0x0f60:  c74a 460f fc08 bd12 b2f4 38bf 460c 40c1  .JF.......8.F.@.
	0x0f70:  8a63 e06f 0a5b eee9 e185 f063 3516 f2ce  .c.o.[.....c5...
	0x0f80:  187e e170 5ec0 9651 b5bf 6d34 5a95 6db2  .~.p^..Q..m4Z.m.
	0x0f90:  919e 3b58 4cf4 5759 310e b437 8145 11cc  ..;XL.WY1..7.E..
	0x0fa0:  bccb 8cb0 33ad a250 355f 643d 8e81 f083  ....3..P5_d=....
	0x0fb0:  1019 1cab b775 75dc 066b 1306 7ca2 b706  .....uu..k..|...
	0x0fc0:  b9be 2ca0 18f5 281d 4380 0857 2e70 2d4e  ..,...(.C..W.p-N
	0x0fd0:  8db0 65e6 2e6f bccc 7a27 9286 bba8 ee47  ..e..o..z'.....G
	0x0fe0:  00f3 5160 9466 b2ae 7a36 1298 ed1d e9fc  ..Q`.f..z6......
	0x0ff0:  5e19 2ca4 bd7d 6c7a c227 cdae 9160 5611  ^.,..}lz.'...`V.
	0x1000:  7862 6a95 0985 31c9 a7bd ab51 6a4f 0918  xbj...1....QjO..
	0x1010:  c46d eb9a 3268 403b 7284 5b0d 326d 2256  .m..2h@;r.[.2m"V
	0x1020:  aa50 6092 e823 fb71 7660 6f8d 717b fb1e  .P`..#.qv`o.q{..
	0x1030:  3ae8 a79c 9b5f 2859 2051 9181 9d45 e65c  :...._(Y.Q...E.\
	0x1040:  b274 28f6 2862 283f 8f19 bb2c 38ad 7e6f  .t(.(b(?...,8.~o
	0x1050:  b1d8 579e 028a 31af 8239 394b 5296 5b17  ..W...1..99KR.[.
	0x1060:  b3ac 80ad 2e87 444b 4614 6e2e edf5 fba9  ......DKF.n.....
	0x1070:  03
```

7. Uninstall all when finished, to release all resources:
```shell
kubectl kustomize manifests/k8s | kubectl delete -f - -n secrets
```
Output:
```shell
secret "the-secrets-9k62d4tck4" deleted
service "secrets-store" deleted
deployment.apps "secrets-store" deleted
networkpolicy.networking.k8s.io "default-deny-ingress" deleted
networkpolicy.networking.k8s.io "isolate-secret-store" deleted
```
8. If created the cluster using minikube, you can delete the cluster as well:
```shell
minikube delete
```
```shell
🔥  Deleting "minikube" in kvm2 ...
💀  Removed all traces of the "minikube" cluster.
```

