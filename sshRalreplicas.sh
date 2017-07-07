#!/bin/bash
ssh -o "StrictHostKeyChecking no" "$1" ralreplicas "'$2'"
