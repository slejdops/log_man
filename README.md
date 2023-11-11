# logman.py

README.md for Log Rotation and Archiving Script
Overview
This Python script is designed for managing log files in a robust and efficient manner. It facilitates log rotation, archiving of old log files, and offers an option to transfer archived logs to a remote server using SCP (Secure Copy Protocol). The script is versatile and can be configured for different environments and requirements.

Features
Log Rotation: Manages the size of log files, rotating them once they reach a specified size.
Archiving: Compresses and archives old log files, freeing up space while keeping historical data.
SCP Transfer: Option to securely transfer archived logs to a remote server for centralized storage or backup.
Flexible Configuration: Can be easily configured to handle different log file patterns, sizes, and backup strategies.
Dry Run Mode: Simulates actions without making actual changes, useful for testing configurations.
Requirements
Python 3
Paramiko (for SCP functionality)
Installation
Ensure Python 3 is installed on your system. Install Paramiko using pip:

bash
Copy code
pip install paramiko
Usage
The script is executed from the command line with various arguments to specify its behavior:

css
Copy code
python logman.py --log-dir <path_to_log_directory> --log-pattern <log_file_pattern> --archive-dir <path_to_archive_directory> --max-log-size <max_log_file_size> --backup-count <number_of_backups> [--dry-run] [--scp-transfer] [--remote-host <hostname>] [--remote-path <remote_path>] [--ssh-user <username>] [--ssh-password <password>]
Arguments
--log-dir: Directory containing the log files.
--log-pattern: Regex pattern to match log files for rotation.
--archive-dir: Directory to store archived logs.
--max-log-size: Maximum size of a log file before it's rotated (e.g., 5M, 10G).
--backup-count: Number of backup files to keep.
--dry-run: Simulate actions without making any changes.
--scp-transfer: Enable SCP transfer of archived files.
--remote-host: Hostname or IP of the remote server (required if --scp-transfer is used).
--remote-path: Remote path for the SCP transfer (required if --scp-transfer is used).
--ssh-user: SSH username for the remote server (required if --scp-transfer is used).
--ssh-password: SSH password for the remote server (required if --scp-transfer is used).
Logging
The script includes an internal logging system for monitoring its operations and troubleshooting.

Examples
Rotate and archive logs in /var/logs, keeping a maximum file size of 5MB and up to 3 backups:

css
Copy code
python logman.py --log-dir /var/logs --log-pattern ".*\.log" --archive-dir /var/archive --max-log-size 5M --backup-count 3
Rotate, archive, and transfer logs to a remote server:

css
Copy code
python logman.py --log-dir /var/logs --log-pattern ".*\.log" --archive-dir /var/archive --max-log-size 5M --backup-count 3 --scp-transfer --remote-host 192.168.1.100 --remote-path /remote/archive --ssh-user user --ssh-password pass
