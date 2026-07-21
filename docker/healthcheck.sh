#!/bin/sh

# Perform request to health API
curl -f http://localhost:5000/health || exit 1
