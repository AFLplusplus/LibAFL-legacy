#!/bin/sh

ipcrm -m $(ipcs -m | tail -n +4 | cut -d ' ' -f2-3) 2>/dev/null || echo "No maps found"
#on mac: ipcrm shm $(ipcs -m | tail -n +4 | cut -d ' ' -f2) 2>/dev/null || echo "No maps found"