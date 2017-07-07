#!/bin/bash
ssh -o "StrictHostKeyChecking no" "$1" ls "'$2'"

