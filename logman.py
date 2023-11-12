#!/usr/bin/env python3

import os
import shutil
import logging
import logging.handlers
import zipfile
import argparse
import paramiko
import re
import errno
import traceback

def parse_size(size_str):
    """
    Converts a size string (like 1M, 20G, 45K) into bytes.
    """
    units = {'K': 1024, 'M': 1024**2, 'G': 1024**3}
    size_str = size_str.upper()
    if size_str[-1] in units:
        return int(size_str[:-1]) * units[size_str[-1]]
    return int(size_str)

def initialize_console_logger():
    """
    Initializes and configures the logger to output to the console.
    """
    logger = logging.getLogger("ScriptLogger")
    logger.setLevel(logging.INFO)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(console_handler)
    return logger

def setup_rotating_logger(log_file, max_log_size, backup_count):
    """
    Configures a rotating logger for application logs.
    """
    logger = logging.getLogger("RotatingLog")
    logger.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=max_log_size, backupCount=backup_count)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def is_file_open(file_path):
    """
    Checks if a file is currently open.
    """
    try:
        if os.name == 'posix':
            fd = os.open(file_path, os.O_WRONLY | os.O_CREAT, 0o777)
            os.close(fd)
        elif os.name == 'nt':
            with open(file_path, 'a'):
                pass
        return False
    except (OSError, IOError) as e:
        if e.errno in [errno.EACCES, errno.EWOULDBLOCK, errno.EPERM]:
            return True
        raise


def zip_and_archive_logs(log_file, archive_dir, backup_count, script_logger, dry_run=False):
    """
    Archives older log files after rotation.
    """
    script_logger.info(f"Preparing to zip and archive log file: {log_file}")
    for i in range(1, backup_count + 1):
        backup_file = f"{log_file}.{i}"
        if os.path.exists(backup_file) and not is_file_open(backup_file):
            zip_path = f"{archive_dir}/{os.path.basename(backup_file)}.zip"
            action = "Archiving" if not dry_run else "[Dry Run] Would archive"
            script_logger.info(f"{action}: {backup_file}")

            if not dry_run:
                try:
                    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        zipf.write(backup_file, os.path.basename(backup_file))
                    os.remove(backup_file)
                    script_logger.info(f"Archived and moved {backup_file} to {archive_dir}")
                except Exception as e:
                    script_logger.error(f"Error while archiving {backup_file}: {e}")


def scp_transfer(local_path, remote_path, hostname, username, password, port=22, script_logger=None, dry_run=False):
    """
    Transfers a file to a remote server using SCP.
    """
    script_logger.info(f"Transferring: {local_path} to {remote_path} on {hostname}")
    if dry_run:
        script_logger.info(f"[Dry Run] Would transfer: {local_path} to {remote_path} on {hostname}")
        return

    if not os.path.exists(local_path):
        script_logger.error(f"Local file does not exist: {local_path}")
        return

    script_logger.info(f"Transferring: {local_path} to {remote_path} on {hostname}")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        script_logger.info(f"Connecting to {hostname}...")
        ssh.connect(hostname, port, username, password, timeout=10)  # Added timeout
        with ssh.open_sftp() as sftp:
            sftp.put(local_path, remote_path)
            script_logger.info(f"Successfully transferred {local_path} to {remote_path} on {hostname}")
    except Exception as e:
        script_logger.error(f"Failed to transfer file: {e}")
        script_logger.error("Traceback: " + traceback.format_exc())  # Detailed traceback
    finally:
        ssh.close()


def find_logs(log_dir, log_pattern, script_logger):
    """
    Retrieves log files matching a given pattern.
    """
    script_logger.info(f"Searching for log files in {log_dir} matching pattern {log_pattern}")
    return [os.path.join(log_dir, file) for file in os.listdir(log_dir) if re.match(log_pattern, file)]


def main(log_dir, log_pattern, archive_dir, max_log_size, backup_count, dry_run=False, enable_scp_transfer=False,
         remote_host=None, remote_path=None, ssh_user=None, ssh_password=None, script_logger=None):
    """
    Main process for log file rotation, archiving, and optional SCP transfer.
    """
    matched_logs = find_logs(log_dir, log_pattern, script_logger)
    if not matched_logs:
        script_logger.info("No log files found matching the pattern.")
        return

    # Ensure archive directory exists
    for log_file in matched_logs:
        logger = setup_rotating_logger(log_file, max_log_size, backup_count)
        zip_and_archive_logs(log_file, archive_dir, backup_count, script_logger, dry_run)

        if enable_scp_transfer:
            for i in range(1, backup_count + 1):
                zip_file = os.path.join(archive_dir, f"{os.path.basename(log_file)}.{i}.zip")
                script_logger.info(f"Checking for zip file: {zip_file}")
                if os.path.exists(zip_file):
                    script_logger.info(f"Found zip file for transfer: {zip_file}")
                    remote_file_path = os.path.join(remote_path or '', os.path.basename(zip_file))
                    scp_transfer(zip_file, remote_file_path, remote_host, ssh_user, ssh_password, script_logger=script_logger, dry_run=bool(dry_run))
                else:
                    script_logger.error(f"Zip file not found: {zip_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log rotation and archiving script.")
    parser.add_argument("--log-dir", type=str, required=True, help="Directory containing the log files.")
    parser.add_argument("--log-pattern", type=str, required=True, help="Regex pattern to match log files.")
    parser.add_argument("--archive-dir", type=str, required=True, help="Directory to store archived logs.")
    parser.add_argument("--max-log-size", type=str, default="5M", help="Max log file size before rotation (e.g. 5M, 10G).")
    parser.add_argument("--backup-count", type=int, default=3, help="Number of backups to keep.")
    parser.add_argument("--dry-run", action="store_true", help="Simulates actions without making changes.")
    parser.add_argument("--enable-scp-transfer", action="store_true", help="Enable SCP transfer of archived files.")
    parser.add_argument("--remote-host", type=str, help="Hostname or IP of the remote server.")
    parser.add_argument("--remote-path", type=str, help="Remote path for the SCP transfer.")
    parser.add_argument("--ssh-user", type=str, help="SSH username for the remote server.")
    parser.add_argument("--ssh-password", type=str, help="SSH password for the remote server.")

    args = parser.parse_args()
    
    script_logger = initialize_console_logger()

    main(args.log_dir, args.log_pattern, args.archive_dir, parse_size(args.max_log_size), args.backup_count, 
         dry_run=args.dry_run, enable_scp_transfer=args.enable_scp_transfer, remote_host=args.remote_host, 
         remote_path=args.remote_path, ssh_user=args.ssh_user, ssh_password=args.ssh_password, 
         script_logger=script_logger)
