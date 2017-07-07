#!/bin/bash
ssh -o "StrictHostKeyChecking no" "$1" cat "'$2'"
