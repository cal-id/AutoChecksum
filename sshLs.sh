#!/bin/bash
ssh -o "StrictHostKeyChecking no" "root@$1" ls "'$2'"

