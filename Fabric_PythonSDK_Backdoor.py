#!/usr/bin/env python

import os
import random
import string
from datetime import datetime, timedelta

from azure.identity import ClientSecretCredential
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.models import RoleAssignmentCreateParameters
from azure.core.exceptions import HttpResponseError

# Service Principal credentials
os.environ["AZURE_TENANT_ID"] = "TenantID"
os.environ["AZURE_CLIENT_ID"] = "ClientID"
os.environ["AZURE_CLIENT_SECRET"] = "Secret"
os.environ["AZURE_SUBSCRIPTION_ID"] = "SubscriptionID"
os.environ["AZURE_RESOURCE_GROUP"] = "ResourceGroupName"
tenant_id = os.environ.get("AZURE_TENANT_ID", "your-tenant-id")
client_id = os.environ.get("AZURE_CLIENT_ID", "your-client-id")
client_secret = os.environ.get("AZURE_CLIENT_SECRET", "your-client-secret")

# Azure configuration
subscription_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "your-subscription-id")
location = "eastus"
resource_group_name = "Fabric2"

# VM configuration
vm_name = "linux-demo-vm"
vm_username = "azureuser"
vm_password = "".join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(16))
managed_identity_name = "demo-msi"

# Role definition ID for Contributor role
contributor_role_id = "b24988ac-6180-42a0-ab88-20f7382dd24c"

def main():
    # Create client credential
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret
    )
    
    # Create clients
    resource_client = ResourceManagementClient(credential, subscription_id)
    msi_client = ManagedServiceIdentityClient(credential, subscription_id)
    compute_client = ComputeManagementClient(credential, subscription_id)
    network_client = NetworkManagementClient(credential, subscription_id)
    auth_client = AuthorizationManagementClient(credential, subscription_id)
    
    # Register required resource providers
    register_providers(resource_client)
    
    # Create or check resource group
    create_resource_group(resource_client, resource_group_name, location)
    
    # Create managed identity
    identity = create_managed_identity(msi_client, resource_group_name, managed_identity_name, location)
    print(f"Created managed identity: {identity.name} with ID: {identity.id}")
    
    # Assign Contributor role to the managed identity
    role_assignment = assign_role(
        auth_client,
        identity.principal_id,
        contributor_role_id,
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}"
    )
    print(f"Assigned Contributor role to managed identity")
    
    # Create network resources
    vnet_name = f"{vm_name}-vnet"
    subnet_name = "default"
    nic_name = f"{vm_name}-nic"
    ip_name = f"{vm_name}-ip"
    nsg_name = f"{vm_name}-nsg"
    
    vnet, subnet = create_vnet(network_client, resource_group_name, location, vnet_name, subnet_name)
    nsg = create_nsg(network_client, resource_group_name, location, nsg_name)
    nic = create_nic(network_client, resource_group_name, location, nic_name, subnet.id, ip_name)
    
    # Create Linux VM with managed identity
    vm = create_linux_vm(
        compute_client,
        resource_group_name,
        location,
        vm_name,
        nic.id,
        vm_username,
        vm_password,
        identity.id
    )
    
    # Get the public IP address for SSH access
    ip_info = network_client.public_ip_addresses.get(resource_group_name, ip_name)
    
    print("\n" + "="*50)
    print(f"DEPLOYMENT COMPLETED SUCCESSFULLY")
    print("="*50)
    print(f"VM Name: {vm_name}")
    print(f"Username: {vm_username}")
    print(f"Password: {vm_password}")  # In production, use a more secure way to handle passwords
    print(f"SSH Command: ssh {vm_username}@{ip_info.ip_address}")
    print(f"Managed Identity: {managed_identity_name}")
    print("="*50)


def register_providers(resource_client):
    """Register necessary Azure resource providers."""
    providers_to_register = [
        "Microsoft.ManagedIdentity",
        "Microsoft.Compute",
        "Microsoft.Network",
        "Microsoft.Authorization"
    ]
    
    for provider in providers_to_register:
        print(f"Registering provider: {provider}")
        resource_client.providers.register(provider)
        # Note: Registration can take time to complete. In a production scenario,
        # you might want to poll for completion.


def create_resource_group(resource_client, resource_group_name, location):
    """Create a resource group if it doesn't exist."""
    try:
        rg = resource_client.resource_groups.get(resource_group_name)
        print(f"Using existing resource group: {resource_group_name}")
        return rg
    except HttpResponseError:
        print(f"Creating resource group: {resource_group_name}")
        return resource_client.resource_groups.create_or_update(
            resource_group_name,
            {"location": location}
        )


def create_managed_identity(msi_client, resource_group_name, identity_name, location):
    """Create a user-assigned managed identity."""
    try:
        return msi_client.user_assigned_identities.get(resource_group_name, identity_name)
    except HttpResponseError:
        # Create the managed identity
        identity = msi_client.user_assigned_identities.create_or_update(
            resource_group_name,
            identity_name,
            {"location": location}
        )
        
        # Add a small delay to allow for replication
        print("Waiting for managed identity to propagate...")
        import time
        time.sleep(30)  # Wait 30 seconds for replication
        
        return identity


def assign_role(auth_client, principal_id, role_definition_id, scope):
    """Assign role to the managed identity."""
    # Generate a random UUID for the role assignment name
    role_assignment_name = f"{principal_id}-{role_definition_id}"[:36]
    
    role_assignment_params = RoleAssignmentCreateParameters(
        role_definition_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_definition_id}",
        principal_id=principal_id,
        principal_type="ServicePrincipal"  # Specify principal type to avoid replication delay issues
    )
    
    try:
        return auth_client.role_assignments.create(
            scope=scope,
            role_assignment_name=role_assignment_name,
            parameters=role_assignment_params
        )
    except HttpResponseError as e:
        # If role assignment already exists, continue
        if "already exists" in str(e):
            print(f"Role assignment already exists for principal {principal_id}")
            return None
        raise


def create_vnet(network_client, resource_group_name, location, vnet_name, subnet_name):
    """Create virtual network and subnet."""
    try:
        vnet = network_client.virtual_networks.get(resource_group_name, vnet_name)
        subnet = network_client.subnets.get(resource_group_name, vnet_name, subnet_name)
        print(f"Using existing vnet: {vnet_name} and subnet: {subnet_name}")
        return vnet, subnet
    except HttpResponseError:
        print(f"Creating vnet: {vnet_name} and subnet: {subnet_name}")
        vnet_params = {
            'location': location,
            'address_space': {
                'address_prefixes': ['10.0.0.0/16']
            },
            'subnets': [
                {
                    'name': subnet_name,
                    'address_prefix': '10.0.0.0/24'
                }
            ]
        }
        
        vnet = network_client.virtual_networks.begin_create_or_update(
            resource_group_name,
            vnet_name,
            vnet_params
        ).result()
        
        subnet = network_client.subnets.get(
            resource_group_name,
            vnet_name,
            subnet_name
        )
        
        return vnet, subnet


def create_nsg(network_client, resource_group_name, location, nsg_name):
    """Create network security group with SSH access from the internet."""
    try:
        nsg = network_client.network_security_groups.get(resource_group_name, nsg_name)
        print(f"Using existing NSG: {nsg_name}")
        return nsg
    except HttpResponseError:
        print(f"Creating NSG: {nsg_name} with SSH access rule")
        nsg_params = {
            'location': location,
            'security_rules': [
                {
                    'name': 'AllowSSH',
                    'protocol': 'Tcp',
                    'source_port_range': '*',
                    'destination_port_range': '22',
                    'source_address_prefix': '*',  # Allow from any source (internet)
                    'destination_address_prefix': '*',
                    'access': 'Allow',
                    'priority': 100,
                    'direction': 'Inbound',
                    'description': 'Allow SSH access from the internet'
                }
            ]
        }
        
        return network_client.network_security_groups.begin_create_or_update(
            resource_group_name,
            nsg_name,
            nsg_params
        ).result()


def create_nic(network_client, resource_group_name, location, nic_name, subnet_id, ip_name):
    """Create network interface with public IP and associate with NSG."""
    try:
        nic = network_client.network_interfaces.get(resource_group_name, nic_name)
        print(f"Using existing NIC: {nic_name}")
        return nic
    except HttpResponseError:
        print(f"Creating NIC: {nic_name} with public IP: {ip_name}")
        
        # Create public IP
        public_ip_params = {
            'location': location,
            'sku': {
                'name': 'Standard'
            },
            'public_ip_allocation_method': 'Static',
            'public_ip_address_version': 'IPv4'
        }
        
        public_ip = network_client.public_ip_addresses.begin_create_or_update(
            resource_group_name,
            ip_name,
            public_ip_params
        ).result()
        
        # Get NSG
        nsg_name = f"{vm_name}-nsg"
        try:
            nsg = network_client.network_security_groups.get(resource_group_name, nsg_name)
        except HttpResponseError:
            # Create NSG if it doesn't exist
            nsg = create_nsg(network_client, resource_group_name, location, nsg_name)
        
        # Create NIC with NSG associated
        nic_params = {
            'location': location,
            'ip_configurations': [
                {
                    'name': 'ipconfig1',
                    'subnet': {
                        'id': subnet_id
                    },
                    'public_ip_address': {
                        'id': public_ip.id
                    }
                }
            ],
            'network_security_group': {
                'id': nsg.id
            }
        }
        
        nic = network_client.network_interfaces.begin_create_or_update(
            resource_group_name,
            nic_name,
            nic_params
        ).result()
        
        # Once NIC is created, print the public IP address for SSH access
        ip_info = network_client.public_ip_addresses.get(resource_group_name, ip_name)
        print(f"VM will be accessible via SSH at: {ip_info.ip_address}")
        
        return nic


def create_linux_vm(compute_client, resource_group_name, location, vm_name, nic_id, 
                    admin_username, admin_password, identity_id):
    """Create a Linux virtual machine with a managed identity attached."""
    print(f"Creating VM: {vm_name}")
    
    vm_params = {
        'location': location,
        'os_profile': {
            'computer_name': vm_name,
            'admin_username': admin_username,
            'admin_password': admin_password,
            'linux_configuration': {
                'disable_password_authentication': False
            }
        },
        'hardware_profile': {
            'vm_size': 'Standard_DS1_v2'
        },
        'storage_profile': {
            'image_reference': {
                'publisher': 'Canonical',
                'offer': 'UbuntuServer',
                'sku': '18.04-LTS',
                'version': 'latest'
            },
            'os_disk': {
                'create_option': 'FromImage',
                'managed_disk': {
                    'storage_account_type': 'Premium_LRS'
                }
            }
        },
        'network_profile': {
            'network_interfaces': [
                {
                    'id': nic_id,
                    'primary': True
                }
            ]
        },
        'identity': {
            'type': 'UserAssigned',
            'user_assigned_identities': {
                identity_id: {}
            }
        }
    }
    
    return compute_client.virtual_machines.begin_create_or_update(
        resource_group_name,
        vm_name,
        vm_params
    ).result()


if __name__ == "__main__":
    main()
