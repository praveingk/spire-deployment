import subprocess
import shlex
from kubernetes import client, config
import socket
import time
from kubernetes.client import ApiException
from kubernetes.utils import create_from_yaml
import urllib.request
import os
import base64
from datetime import datetime

def run_command(command, cwd="."):
    """
    Execute a system command and return the output.
    
    Args:
        command (str): The command to execute.
    
    Returns:
        tuple: A tuple containing (return_code, stdout, stderr).
    """
    try:
        print(f">>>>{command}")
        op = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, cwd=cwd).decode('utf-8')
        return op
    except Exception as error:
        print("Failed to run : %s",
                        error.output.decode('utf-8'))

def init_kubernetes_client():
    """
    Initialize the Kubernetes client configuration.
    """
    try:
        client = config.new_client_from_config("/etc/rancher/k3s/k3s.yaml")
        return client
    except config.config_exception.ConfigException as error:
        raise error

def list_pods(namespace="default"):
    """
    List pods in the specified namespace.
    
    Args:
        namespace (str): The namespace to list pods from. Defaults to "default".
    
    Returns:
        list: A list of pod names.
    """
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(namespace)
    return [pod.metadata.name for pod in pods.items]

def install_k3s():
    """
    Install k3s with specified options.
    
    Returns:
        tuple: A tuple containing (return_code, stdout, stderr).
    """
    command = "curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644 --disable traefik"
    return run_command(command)

def label_node(k3s_client, node_name, label_key, label_value):
    """
    Label a node with the specified key and value.
    """
    # Override the SSL verification (ignore SSL certificate errors)
    configuration = client.Configuration()
    configuration.verify_ssl = False

    try:
        api = client.CoreV1Api(k3s_client)
        body = {
            "metadata": {
                "labels": {label_key: label_value}
            }
        }
        api.patch_node(node_name, body)
        return True
    except Exception as e:
        print(f"Error labeling node: {e}")
        return False
    
def wait_for_ready_deployment(k3s_client, name, namespace="default", timeout_seconds=300):
    """Waits until the pod status is running"""
    start_time = time.time()
    end_time = start_time + timeout_seconds
    core_api = client.AppsV1Api(k3s_client)
    while time.time() < end_time:
        try:
            deployment = core_api.read_namespaced_deployment(
                name, namespace=namespace)
        except client.exceptions.ApiException:
            continue
        if deployment.status.replicas == None:
            continue
        if deployment.status.ready_replicas == deployment.status.replicas:
            print(f"{namespace}/{name} deployment is ready!")
            return True
        time.sleep(0.1)    

def deploy_nginx_ingress(k3s_client):
    url = 'https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml'

    # Download the YAML content
    response = urllib.request.urlopen(url)
    yaml_content = response.read().decode('utf-8')
    # Save the content to a temporary file
    with open("deploy.yaml", "w") as f:
        f.write(yaml_content)

    try:
        create_from_yaml(k3s_client, 'deploy.yaml')
        print("Ingress Resources applied successfully!")
    except ApiException as e:
        print(f"Error applying the resources: {e}")

def deploy_spire(k3s_client):
    run_command("curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3")
    run_command("chmod 700 get_helm.sh")
    run_command("./get_helm.sh")

    run_command("mkdir -p spire")
    run_command("git clone -b spire-0.21.0 https://github.com/spiffe/helm-charts-hardened.git", "spire/")
    os.environ["APP_DOMAIN"] = "spire-server.local"
    print(f"{os.environ.get('APP_DOMAIN')}")
    run_command("KUBECONFIG=/etc/rancher/k3s/k3s.yaml helm upgrade --install --create-namespace -n spire-mgmt spire-crds spire/helm-charts-hardened/charts/spire-crds")
    run_command("KUBECONFIG=/etc/rancher/k3s/k3s.yaml helm upgrade --install --create-namespace -n spire-mgmt spire spire/helm-charts-hardened/charts/spire -f artifacts/my-values.yaml --set global.spire.namespaces.create=true --set global.spire.trustDomain=$APP_DOMAIN --values spire/helm-charts-hardened/examples/tornjak/values.yaml --values spire/helm-charts-hardened/examples/tornjak/values-ingress.yaml --render-subchart-notes --debug")

def create_tls_secret(k3s_client, secret_name, cert_file, key_file, namespace):
    try:
        with open(cert_file, "rb") as cert:
            cert_data = cert.read()
        with open(key_file, "rb") as key:
            key_data = key.read()
    except IOError as e:
        print(f"Error reading certificate/key files: {e}")
        return

    # Base64 encode the certificate and key (K8s expects this)
    cert_b64 = base64.b64encode(cert_data).decode('utf-8')
    key_b64 = base64.b64encode(key_data).decode('utf-8')

    # Create the secret metadata
    metadata = client.V1ObjectMeta(name=secret_name, namespace=namespace)

    # Create the secret data (as a dictionary)
    secret_data = {
        "tls.crt": cert_b64,
        "tls.key": key_b64
    }

    # Define the secret
    secret = client.V1Secret(
        metadata=metadata,
        type="kubernetes.io/tls",
        data=secret_data
    )

    # Create a CoreV1Api instance
    api = client.CoreV1Api(k3s_client)

    # Create the secret in the specified namespace
    try:
        api.create_namespaced_secret(namespace=namespace, body=secret)
        print(f"TLS secret '{secret_name}' created successfully in the '{namespace}' namespace.")
    except ApiException as e:
        print(f"Exception when creating the TLS secret: {e}")

def add_tls_secret_to_ingress(k3s_client, ingress_name, namespace, secret_name, host_name):
    # Create an API instance for the NetworkingV1 API
    api_instance = client.NetworkingV1Api(k3s_client)

    try:
        # Fetch the Ingress resource
        ingress = api_instance.read_namespaced_ingress(name=ingress_name, namespace=namespace)

        # Check if the ingress already has a tls section
        if ingress.spec.tls:
            for tls in ingress.spec.tls:
                # Check if the desired host exists in the current tls configuration
                if host_name in tls.hosts:
                    # Add or update the secretName for the matching host
                    tls.secret_name = secret_name
                    print(f"Added/Updated secretName '{secret_name}' for host '{host_name}'.")
                    break
            else:
                print(f"Host '{host_name}' not found in the existing TLS configuration.")
        else:
            print(f"Ingress '{ingress_name}' does not have a TLS section.")

        # Update the Ingress resource with the modified tls configuration
        api_instance.replace_namespaced_ingress(name=ingress_name, namespace=namespace, body=ingress)
        print(f"Ingress '{ingress_name}' updated successfully in the '{namespace}' namespace.")

    except ApiException as error:
        print(f"Exception when updating Ingress: {error}")

def rollout_restart_deployment(k3s_client, deployment_name, namespace):
    api_instance = client.AppsV1Api(k3s_client)

    try:
        # Fetch the deployment
        deployment = api_instance.read_namespaced_deployment(name=deployment_name, namespace=namespace)

        # Modify the annotations to trigger a rollout restart
        if not deployment.spec.template.metadata.annotations:
            deployment.spec.template.metadata.annotations = {}

        # Add a new annotation with the current timestamp
        deployment.spec.template.metadata.annotations['kubectl.kubernetes.io/restartedAt'] = datetime.now().isoformat()

        # Update the deployment with the new annotation (this triggers a restart)
        api_instance.patch_namespaced_deployment(name=deployment_name, namespace=namespace, body=deployment)
        print(f"Deployment '{deployment_name}' successfully restarted in the '{namespace}' namespace.")

    except ApiException as error:
        print(f"Exception when restarting deployment: {error}")

def add_entries_to_hosts(node_ip):
    hosts_entries = [
        f"{node_ip} tornjak-backend.spire-server.local",
        f"{node_ip} spire-server.spire-server.local",
        f"{node_ip} oidc-discovery.spire-server.local",
        f"{node_ip} tornjak-frontend.spire-server.local",
    ]

    hosts_file = "/etc/hosts"

    try:
        # Read the current /etc/hosts file content
        with open(hosts_file, "r") as file:
            lines = file.readlines()

        # Check if the entries already exist
        new_entries = [entry for entry in hosts_entries if entry not in lines]

        # If new entries exist, append them to the file
        if new_entries:
            with open(hosts_file, "a") as file:
                for entry in new_entries:
                    file.write(f"{entry}\n")
            print(f"Added {len(new_entries)} new entries to {hosts_file}.")
        else:
            print("All entries are already present in /etc/hosts.")

    except PermissionError:
        print("Permission denied. Please run the script with elevated privileges (sudo).")
    except Exception as e:
        print(f"Error: {e}")

def get_node_ip(k3s_client, hostname):
    # Create an instance of the CoreV1Api
    v1 = client.CoreV1Api(k3s_client)

    try:
        # Get the details of the specific node by hostname
        node = v1.read_node(name=hostname)

        # Extract the node's internal IP from its addresses
        for address in node.status.addresses:
            if address.type == 'InternalIP':
                node_ip = address.address
                print(f"Node: {hostname}, Internal IP: {node_ip}")
                return node_ip

    except client.rest.ApiException as e:
        if e.status == 404:
            print(f"Node with hostname '{hostname}' not found.")
        else:
            print(f"Error fetching node: {e}")
    except Exception as e:
        print(f"Error: {e}")

def install_nginx():
    """
    Install Nginx using the system's package manager (apt for Ubuntu/Debian).
    """
    try:
        # Update the package list
        print("Updating package list...")
        subprocess.run(["sudo", "apt", "update"], check=True)

        # Install Nginx
        print("Installing Nginx...")
        subprocess.run(["sudo", "apt", "install", "-y", "nginx"], check=True)

        # Enable and start the Nginx service
        print("Enabling and starting Nginx...")
        subprocess.run(["sudo", "systemctl", "enable", "nginx"], check=True)
        subprocess.run(["sudo", "systemctl", "start", "nginx"], check=True)

        print("Nginx installation complete and service is running.")
    except subprocess.CalledProcessError as e:
        print(f"Error during installation: {e}")

def setup_nginx() :
    run_command("sudo cp artifacts/default /etc/nginx/sites-available/default")
    run_command("sudo systemctl restart nginx")

if __name__ == "__main__":
    # Install k3s
    install_k3s()
    print(f"K3s installed")
    time.sleep(5)
    k3s_client = init_kubernetes_client()
    hostname = socket.gethostname()
    print(f"Labelling {hostname} as ingress-ready")
    success = label_node(k3s_client, hostname, "ingress-ready", "true")

    deploy_nginx_ingress(k3s_client)
    wait_for_ready_deployment(k3s_client, "ingress-nginx-controller", "ingress-nginx")
    time.sleep(10)
    deploy_spire(k3s_client)
    wait_for_ready_deployment(k3s_client, "spire-spiffe-oidc-discovery-provider", "spire-server")
    wait_for_ready_deployment(k3s_client, "spire-tornjak-frontend", "spire-server")
    print(f"Spire deployment setup & ready!!")
    create_tls_secret(
        k3s_client,
        secret_name="nginx-spire-secret",
        cert_file="certs/spire-server.local/cert.pem",
        key_file="certs/spire-server.local/key.pem",
        namespace="spire-server"
    )

    add_tls_secret_to_ingress(
        k3s_client,
        ingress_name="spire-server",
        namespace="spire-server",
        secret_name="nginx-spire-secret",
        host_name="spire-server.spire-server.local"
    )
    add_tls_secret_to_ingress(
        k3s_client,
        ingress_name="spire-tornjak",
        namespace="spire-server",
        secret_name="nginx-spire-secret",
        host_name="tornjak-backend.spire-server.local"
    )
    add_tls_secret_to_ingress(
        k3s_client,
        ingress_name="spire-spiffe-oidc-discovery-provider",
        namespace="spire-server",
        secret_name="nginx-spire-secret",
        host_name="oidc-discovery.spire-server.local"
    )
    add_tls_secret_to_ingress(
        k3s_client,
        ingress_name="spire-tornjak-frontend",
        namespace="spire-server",
        secret_name="nginx-spire-secret",
        host_name="tornjak-frontend.spire-server.local"
    )
    print("Added nginx-spire-secret to ingress!")
    rollout_restart_deployment(
        k3s_client,
        deployment_name="ingress-nginx-controller",
        namespace="ingress-nginx"
    )
    print("Restarted ingress-controller!")

    node_ip = get_node_ip(k3s_client, hostname)
    add_entries_to_hosts(node_ip)
    install_nginx()
    setup_nginx()

    time.sleep(10)
    print("Testing connectivity..")
    op = run_command("curl https://tornjak-backend.spire-server.local --cacert certs/cert.pem")

    if op is not None and "Welcome to the Tornjak Backend" not in op:
        print(op)
        print("Failed to reach tornjak backend")
    else:
        print(f"Success: {op}")
