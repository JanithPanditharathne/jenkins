# Build Instructions

## Build
    # Login to Docker Repository
    docker login

    docker build -t janithp/jenkins-nginx-proxy:1.0.0 .
    docker push janithp/jenkins-nginx-proxy:1.0.0

# Deployment Instructions

## Setup Environment

    # You must run this script as the 'root' user
    chmod +x ./scripts/docker-setup.sh
    ./scripts/docker-setup.sh

## Deploy the Docker Stack

    # Login to Docker Repository
    docker login

    # Create a directory for SSL file mount
    mkdir -p /opt/jenkins-deploy/certs

    # Generate custom DH parameters
    openssl dhparam -out /opt/jenkins-deploy/certs/dhparams.pem 2048

    # Create a Self-Signed SSL certificate for *.zone24x7.lk
    openssl req -newkey rsa:2048 -nodes -keyout /etc/nginx/ssl/selfsign.key -x509 -days 365 -out /etc/nginx/ssl/selfsign.crt -subj "/C=LK/ST=WP/L=Colombo/O=Example (Private) Limited/CN=*.example.com"

    # Deploy the Stack
    docker stack deploy --prune --with-registry-auth --resolve-image=always --compose-file jenkins-stack.yml jenkins-prod
​