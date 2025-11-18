#!/bin/bash

# Requirements:
# KSCTL CLI must be installed and configured
# jq must be installed for JSON parsing

json='[
  {
    "name": "Password Policy Modified",
    "source_type": "server_record",
    "condition": "input.message == \"Update Passphrase Policy\" \ninput.success == true \ninput.service_name == \"platform\" \n",
    "description": "The system password policy has been modified",
    "severity": "info",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Backup Key Downloaded",
    "source_type": "server_record",
    "condition": "input.message == \"Download backup key\" \ninput.success == true \ninput.service_name == \"backup\" \n",
    "description": "A backup archive encryption key has been downloaded",
    "severity": "info",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Quorum Activated",
    "source_type": "server_record",
    "condition": "input.message == \"Activate Quorum\" \ninput.success == true \n",
    "description": "A quorum has been activated",
    "severity": "info",
    "threshold": 0,
    "interval": 0
  }, 
  {
    "name": "Quorum Profile Updated",
    "source_type": "server_record",
    "condition": "input.message == \"Update Quorum Profile\" \ninput.success == true \ninput.service_name == \"platform\" \n",
    "description": "A quorum policy has been enabled or disabled",
    "severity": "info",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Quorum Policy Updated",
    "source_type": "server_record",
    "condition": "input.message == \"Update Quorum Policy\" \ninput.success == true \n",
    "description": "A quorum policy has been modified",
    "severity": "info",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "CTE Communication Failure",
    "source_type": "server_record",
    "condition": "input.details.mid == \"COM4633W\" \ninput.event == \"SOAP client error\" \n",
    "description": "\"There was a communication failure with the Key Manager",
    "severity": "warning",
    "threshold": 1,
    "interval": 120
  },
  {
    "name": "CTE Guard timed out",
    "source_type": "server_record",
    "condition": "input.details.mid == \"CGA3144E\" \ninput.event == \"BadGrd TimedOut\" \n",
    "description": "Path not guarded.  Operation timed out.",
    "severity": "warning",
    "threshold": 1,
    "interval": 120
  },
  {
    "name": "CTE Error updating Client",
    "source_type": "server_record",
    "condition": "input.message == \"Update CTE Client\" \ninput.success == false \n",
    "description": "Unable to update CTE client",
    "severity": "error",
    "threshold": 1,
    "interval": 120
  },
  {
    "name": "CTE GuardPoint Deleted",
    "source_type": "server_record",
    "condition": "input.message==\"Delete CTE GuardPoint\"\ninput.success==true",
    "description": "A CTE GuardPoint was deleted from the system",
    "severity": "warning",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Scheduled Job Deleted",
    "source_type": "server_record",
    "condition": "input.message==\"Delete job config\"\ninput.success==true",
    "description": "A job configuration was deleted from the system",
    "severity": "warning",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Client Deleted",
    "source_type": "server_record",
    "condition": "input.message == \"Delete Ciphertrust Manager client\" \ninput.success == true \n",
    "description": "A CipherTrust Client has been deleted",
    "severity": "warning",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Certificate Deleted",
    "source_type": "server_record",
    "condition": "input.message == \"Delete Certificate\" \ninput.success == true \n",
    "description": "A certificate has been deleted",
    "severity": "warning",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Local CA Deleted",
    "source_type": "server_record",
    "condition": "input.message == \"Delete Local CA\" \ninput.success == true \n",
    "description": "A local CA has been deleted",
    "severity": "warning",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Local CA Created",
    "source_type": "server_record",
    "condition": "input.message == \"Create Local CA\" \ninput.success == true \n",
    "description": "New local CA created",
    "severity": "info",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Interface Deleted",
    "source_type": "server_record",
    "condition": "input.message == \"Delete Interface Configuration\" \ninput.success == true \n",
    "description": "A protocol interface has been deleted",
    "severity": "warning",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Interface Modified",
    "source_type": "server_record",
    "condition": "input.message == \"Update Interface Configuration\" \ninput.success == true \n",
    "description": "A protocol interface has been modified",
    "severity": "warning",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Interface Created",
    "source_type": "server_record",
    "condition": "input.message == \"Create Interface Configuration\" \ninput.success == true \n",
    "description": "New protocol interface was created",
    "severity": "info",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Key Deleted",
    "source_type": "server_record",
    "condition": "input.message==\"Delete Key\"\ninput.success==true",
    "description": "A key was deleted from the system",
    "severity": "warning",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Weak AES key created",
    "source_type": "server_record",
    "condition": "input.success\ninput.message == \"Create Key\"\ninput.details.algorithm == \"AES\"\ninput.details.size < 256",
    "description": "AES key should be 256 bits or higher",
    "severity": "info",
    "threshold": 0,
    "interval": 0
  },
  {
    "name": "Weak RSA key created",
    "source_type": "server_record",
    "condition": "input.success\ninput.message == \"Create Key\"\ninput.details.algorithm == \"RSA\"\ninput.details.size <= 1024",
    "description": "RSA key should be 2048 bits or higher",
    "severity": "info",
    "threshold": 0,
    "interval": 0
  }
]'

# Iterate through each alarm in the JSON array
echo "$json" | jq -c '.[]' | while read -r alarm; do
    name=$(echo "$alarm" | jq -r '.name')
    description=$(echo "$alarm" | jq -r '.description')
    severity=$(echo "$alarm" | jq -r '.severity')
    condition=$(echo "$alarm" | jq -r '.condition' | tr -d '\n')
    threshold=$(echo "$alarm" | jq -r '.threshold')
    interval=$(echo "$alarm" | jq -r '.interval')

    ksctl records alarm-configs create -n "$name" -d "$description" -e "$severity" -c "$condition" -t "$threshold" -p "$interval"
done
