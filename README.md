# SPIRE Deployment

This repo provides scripts and artifacts to setup SPIRE server on a k3s deployment in a VM/bare-metal

## Prerequisites

1) Admin privileges to be able to change /etc/hosts, etc.

2) Kubernetes python package
```
sudo pip3 install kubernetes
```

## Start the SPIRE setup in the vm

```
sudo python3 setup.py
```

## Access from laptop/external

    1) Make sure the VM is accessible, and note its IP.
    2) Add the following to /etc/hosts:

    ```
    VMIP tornjak-backend.spire-server.local
    VMIP spire-server.spire-server.local
    VMIP oidc-discovery.spire-server.local
    VMIP tornjak-frontend.spire-server.local
    ```

    Replace VMIP with the actual IP of the VM where SPIRE server deployment is setup.