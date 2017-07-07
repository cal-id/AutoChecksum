#!/bin/bash
ssh -o "StrictHostKeyChecking no" "root@$1" cat "'$2'"
