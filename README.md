# automated-secret-remediation

## Project File Structure
```
project_root/
├── main.py
├── server.py
├── alert_status.json
└── test_files/
    ├── config1.yaml
    ├── config2.yaml
    ├── creds.txt
    ├── script.sh
    ├── creds_active.txt
    ├── creds_inactive.txt
    ├── app.conf
    ├── dummy.txt
    ├── commented.txt
    └── code_snippet.txt


Commands to run 
```
# List all detected flags
python main.py list

# Classify alert <id>
python main.py classify <id>

# Close false positive
python main.py close-fp <id>

# Run server on another terminal
python server.py

# Checks if the exposed password is still active by testing the credentials
python main.py check-active <id>

# Revokes the alert if the password is no longer in use
python main.py revoke <id>

# Shows the current status of the specified alert
python main.py status <id>

# Resets the status of all alerts to open
python main.py reset

```
