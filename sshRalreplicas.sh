#!/bin/bash
ssh -o "StrictHostKeyChecking no" "root@$1" ralreplicas "'$2'"
