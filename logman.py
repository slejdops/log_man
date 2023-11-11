import os
import shutil
import logging
import logging.handlers
import zipfile
import argparse
import paramiko
import re
import errno

def parse_size(size_str):
    """
    Parses a size string (like 1M, 20G, 45K) and converts it into bytes.
    """
    size_str = size_str.upper()
    if size_str.endswith('K'):
        return int(size_str[:-1]) * 1024
    elif size_str.endswith('M'):
        return int(size_str[:-1]) * 1024 * 1024
    elif size_str.endswith('G'):
        return int(size_str[:-1]) * 1024 * 1024 * 1024
    else:
        return int(size_str)

def setup_logger(log_file, max_log_size, backup_count):
    """
    Sets up a rotating logger to handle application logs.
    """
    logger = logging.getLogger("RotatingLog")
    logger.setLevel(logging.INFO)

    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_log_size, backupCount=backup_count
    )
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger

def is_file_open(file_path):
    """
    Checks if a file is open by trying to open it in exclusive mode.
    """
    try:
        if os.name == 'posix':
            fd = os.open(file_path, os.O_EXCL | os.O_RDWR)
            os.close(fd)
        elif os.name == 'nt':
            os.rename(file_path, file_path)
        return False
    except (OSError, IOError) as e:
        if e.errno in [errno.EACCES, errno.EWOULDBLOCK, errno.EPERM]:
            return True
        raise

def zip_and_archive_logs(log_file, archive_dir, backup_count, script_logger, dry_run=False):
    """
    Zips and archives older log files if they are not open.
    """
    for i in range(1, backup_count + 1):
        backup_file = f"{log_file}.{i}"
        if os.path.exists(backup_file):
            if is_file_open(backup_file):
                script_logger.info(f"File {backup_file} is currently in use and will not be archived.")
                continue

            zip_path = f"{backup_file}.zip"
            if dry_run:
                script_logger.info(f"[Dry Run] Would zip: {backup_file}")
                script_logger.info(f"[Dry Run] Would move: {zip_path} to {archive_dir}")
                script_logger.info(f"[Dry Run] Would delete: {backup_file}")
            else:
                try:
                    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                        zipf.write(backup_file, os.path.basename(backup_file))
                    shutil.move(zip_path, os.path.join(archive_dir, os.path.basename(zip_path)))
                    os.remove(backup_file)
                    script_logger.info(f"Archived: {backup_file}")
                except Exception as e:
                    script_logger.error(f"Error while archiving {backup_file}: {e}")

def scp_file(local_path, remote_path, hostname, username, password, port=22, script_logger=None):
    """
    Securely copies a file to a remote server using SCP.
    """
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(hostname, port, username, password)
        with ssh.open_sftp() as sftp:
            sftp.put(local_path, remote_path)
            if script_logger:
                script_logger.info(f"Successfully transferred {local_path} to {remote_path} on {hostname}")
    except Exception as e:
        if script_logger:
            script_logger.error(f"Failed to transfer file: {e}")
    finally:
        ssh.close()

def find_logs(log_dir, log_pattern):
    """
    Finds log files in the specified directory based on the regular expression pattern.
    """
    matched_files = []
    for file in os.listdir(log_dir):
        if re.match(log_pattern, file):
            matched_files.append(os.path.join(log_dir, file))
    return matched_files

def main(log_dir, log_pattern, archive_dir, max_log_size, backup_count, dry_run=False, scp_transfer=False,
         remote_host=None, remote_path=None, ssh_user=None, ssh_password=None, script_logger=None):
    """
    Main function to handle log rotation, archiving, and optional SCP transfer.
    """
    matched_logs = find_logs(log_dir, log_pattern)
    if not matched_logs:
        script_logger.info("No log files found matching the pattern.")
        return

    for log_file in matched_logs:
        if not os.path.exists(archive_dir) and not dry_run:
            os.makedirs(archive_dir)

        logger = setup_logger(log_file, max_log_size, backup_count)

        zip_and_archive_logs(log_file, archive_dir, backup_count, script_logger, dry_run)

        if scp_transfer and not dry_run:
            for i in range(1, backup_count + 1):
                zip_path = f"{log_file}.{i}.zip"
                if os.path.exists(zip_path):
                    scp_file(zip_path, os.path.join(remote_path, os.path.basename(zip_path)),
                             remote_host, ssh_user, ssh_password, script_logger=script_logger)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log rotation and archiving script.",
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("log_dir", type=str, help="Directory containing the log files.")
    parser.add_argument("log_pattern", type=str, help="Regular expression pattern to match log files.")
    parser.add_argument("archive_dir", type=str, help="Path to the archive directory.")
    parser.add_argument("--max-log-size", type=str, default="5M", 
                        help="Maximum size of the log file before rotation (e.g., 1M, 20G, 45K). Default is 5M.")
    parser.add_argument("--backup-count", type=int, default=3, 
                        help="Number of backups to keep before zipping (default: 3).")
    parser.add_argument("--dry-run", action="store_true", 
                        help="Enable dry run mode without making any changes.")
    parser.add_argument("--scp-transfer", action="store_true", help="Enable SCP transfer of archived files.")
    parser.add_argument("--remote-host", type=str, help="Hostname or IP of the remote server.")
    parser.add_argument("--remote-path", type=str, help="Remote path to place the files.")
    parser.add_argument("--ssh-user", type=str, help="SSH username for the remote server.")
    parser.add_argument("--ssh-password", type=str, help="SSH password for the remote server.")

    args = parser.parse_args()

    script_logger = logging.getLogger("ScriptLogger")
    script_logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    script_logger.addHandler(ch)

    if args.scp_transfer and not all([args.remote_host, args.remote_path, args.ssh_user, args.ssh_password]):
        parser.error("SCP transfer requires --remote-host, --remote-path, --ssh-user, and --ssh-password.")

    max_log_size_bytes = parse_size(args.max_log_size)

    main(args.log_dir, args.log_pattern, args.archive_dir, max_log_size_bytes, args.backup_count, 
         dry_run=args.dry_run, scp_transfer=args.scp_transfer, remote_host=args.remote_host, 
         remote_path=args.remote_path, ssh_user=args.ssh_user, ssh_password=args.ssh_password, 
         script_logger=script_logger)
