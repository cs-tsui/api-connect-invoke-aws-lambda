## API Connect - Invoke AWS Lambda with GatewayScript

### Table of Contents

Use API Connect to invoke your Lambda functions directly
- [API Connect - Invoke AWS Lambda with GatewayScript](#api-connect---invoke-aws-lambda-with-gatewayscript)
  - [Table of Contents](#table-of-contents)
- [Usage](#usage)
  - [1) Clone the repo](#1-clone-the-repo)
  - [2) Import the API YAML file into API Connect](#2-import-the-api-yaml-file-into-api-connect)
  - [3) Upload required JavaScript to DataPower Gateway](#3-upload-required-javascript-to-datapower-gateway)
  - [4) Call Lambda Function](#4-call-lambda-function)
- [Notes](#notes)

## Usage

### 1) Clone the repo

`git clone https://github.com/cs-tsui/apic-invoke-aws-lambda.git`

### 2) Import the API YAML file into API Connect

Log into API Manager, go to `Developer`, `Add -> API`, and `Import -> Existing OpenAPI`, and select ther `aws-lambda-proxy-1.0.1.yaml` file. 

### 3) Upload required JavaScript to DataPower Gateway

Make the JavaScript file `aws-v4-sign.js` available to the DataPower gateway, so it may be referenced in the GatewayScript policy.

One quick and dirty way to copy the file into the DataPower gateway is to utilize the `kubectl cp` command to copy the file into the local directory
of the `apiconnect` domain directly. However, this is not recommeded due to the fact that the file will be lost if the gateway is restarted. Only do this for a quick proof of concept or demo purposes.

`kubectl cp ./aws-v4-sign.js minimum-gw-0:opt/ibm/datapower/drouter/local/apiconnect/aws-v4-sign.js`

<br>
Or the more proper way of configuring Datapower V10


Create tar file from the js file.

```
$ tar -czvf apic-domain-local.tar.gz aws-v4-sign.js
a aws-v4-sign.js
```

Check the content, show contain our file

```
$ tar -tzvf apic-domain-local.tar.gz
-rw-r--r--  0 chunsingtsui staff   41734 Nov  3 15:48 aws-v4-sign.js
```

Create `local` config map from the tarball

```
# Switch to the proper namespace where APIC/Gateway is installed
kubens apic 

# Create ConfigMap
kubectl create configmap apicdomain-local \
  --from-file=apic-domain-local.tar.gz
```

Create an empty configmap to be used so the Operator doesn't complain when we edit section in the `additionalDomainConfig` without providing any content.

```
kubectl create configmap empty
```


List out the `gatewayclusters` that we have, and edit the one we want to upload the 
file to.

```
$ kubectl get gatewayclusters                                   
NAME          READY   STATUS    VERSION    RECONCILED VERSION   AGE
minimum-gw    1/2     Pending   10.0.1.0   10.0.1.0-627         5d9h
minimum-gw2   2/2     Running   10.0.1.0   10.0.1.0-627         7h33m

$ kubectl edit gatewayclusters minimum-gw
```


Under `spec`, append this section to reference the `apicdomain-local` and the `empty` ConfigMap we created above.
```
spec:
  ...
  additionalDomainConfig:
  - name: apiconnect
    dpApp:
      config:
      - "empty"
      local:
      - "apicdomain-local"
  ...
```

Now the gateway pod will restart. After it is running again, we can check that the `aws-v4-sign.js` file is
available in the `local` directory.

```
$ kubectl exec minimum-gw-0 -- ls -lah /opt/ibm/datapower/drouter/local/apiconnect/
total 72K
drwxrwxrwx. 3 drouter root 4.0K Nov  3 21:55 .
drwxrwxrwx. 1    1000 root 4.0K Nov  3 21:52 ..
-rw-r--r--. 1 drouter root  41K Nov  3 21:52 aws-v4-sign.js
-rw-r--r--. 1 drouter root  290 Nov  3 21:55 config-sequence.cfg
-rw-------. 1 drouter root 2.8K Nov  3 21:55 config-sequence.log
lrwxrwxrwx. 1 drouter root   53 Nov  3 21:52 tms -> ../../ramdisk2/mnt/raid-volume/raid0/local/apiconnect
drwxr-xr-x. 2 drouter root 4.0K Nov  3 21:55 working
```


### 4) Call Lambda Function

If we've imported and activated our API, we can try out invoking a Lambda function. We'll need a few things:

- API Connect Client ID (if enabled via security policies)
- AWS Access Key/Access Secret
- AWS Lambda function name and region (optionally the function `qualifier`)

In the following example `curl` call, I'm using `region` = `us-east-1` and `func-name` = `js-func`. The `Qualifier` query string can be set to call a specific qualifier for a Lambda function.

The parameters to the APIC front-side includes the above variables in various locations of the URL and header.

`https://gatway-apiconnect.ibm.com/apic-org/sandbox/aws-lambda-proxy/{region}/{func-name}?{Qualifier=1}`

```
$ curl -k --location --request POST 'https://gatway-apiconnect.ibm.com/apic-org/sandbox/aws-lambda-proxy/us-east-1/js-func?Qualifier=1' \
--header 'aws-client-id: <AWS_ACCESS_KEY_ID>' \
--header 'aws-client-secret: <AWS_ACCESS_KEY_SECRET>' \
--header 'X-IBM-Client-Id: <IBM_CLIENT_ID>'

{"statusCode":200,"body":"\"Hello from Lambda 1\""}
```


## Notes

Future improvements can be made to this API to include POSTing a body to the
lambda function. Currently it is not passing the `body` payload to the AWS API Call.

References:
- 