#!/bin/sh

ipcrm shm $(ipcs -m | tail -n +4 | cut -d ' ' -f2) 2>/dev/null || echo "No maps found"