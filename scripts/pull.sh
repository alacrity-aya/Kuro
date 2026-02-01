#!/bin/bash

CLUSTER_NAME="kuro-dev"
IMAGES=("nicolaka/netshoot" "nginx:alpine")

# Color Definitions
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}>>> Fetching node list for cluster: ${CLUSTER_NAME}...${NC}"
NODES=$(kind get nodes --name "${CLUSTER_NAME}")

if [ -z "$NODES" ]; then
    echo "Error: Cluster '${CLUSTER_NAME}' not found or contains no nodes."
    exit 1
fi

# Function to pull all images on a single node
pull_in_node() {
    local node=$1
    echo -e "${BLUE}[${node}] Starting tasks...${NC}"
    
    for img in "${IMAGES[@]}"; do
        echo -e "[${node}] Pulling: $img"
        # Use crictl to pull images inside the node container
        # Redirect output to null; handle errors gracefully to continue the loop
        docker exec "$node" crictl pull "$img" > /dev/null 2>&1
        
        if [ $? -eq 0 ]; then
             echo -e "${GREEN}[${node}] Successfully pulled: $img${NC}"
        else
             echo -e "${RED}[${node}] Failed to pull: $img${NC}"
        fi
    done
    
    echo -e "${GREEN}[${node}] All tasks completed on this node.${NC}"
}

# Execute in parallel
pids=""
for node in $NODES; do
    (pull_in_node "$node") &
    pids="$pids $!"
done

# Wait for all background processes to finish
wait $pids

echo -e "\n${GREEN}>>> Image pull complete across all nodes!${NC}"
