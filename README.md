## Secret Manager

Secret Manager is a Greengrass component that manages sensitive data stored with Greengrass. Today it only
 supports secrets stored in AWS secrets manager. It also provides API's for components to fetch secrets 
 locally. It provides backward compatible v1 secret API's for lambda components as well. Secret Manager 
 component is optional and runs in the same JVM as [kernel](https://github.com/aws/aws-greengrass-kernel). 
 
 ## FAQ
 
 1. How are secrets stored on greengrass device?
 
    Secrets are stored encrypted using a private key provided by the user or by default using the IoT thing 
    key associated with kernel.
    
 2. When are secrets synchronized from the cloud?
 
    Secrets are fetched only with deployments (cloud/local) to kernel. Since secrets are changes less
    frequently in cloud, optimizing for intelligent fetching when device could be offline for longer period
    of time does not have much benefit. Instead, deployment offers the best window, where device needs to 
    have some connectivity to sync with cloud.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the Apache-2.0 License.

