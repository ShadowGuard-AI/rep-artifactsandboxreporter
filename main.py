import argparse
import hashlib
import logging
import os
import shutil
import subprocess
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define some constants
SANDBOX_IMAGE = "ubuntu:22.04"  # Pinned tag, not the mutable latest tag
SANDBOX_USER = "65534:65534"  # Non-root user (nobody) inside the container
CONTAINER_NAME = "artifact_sandbox"
REPORT_FILE = "sandbox_report.txt"
TIMEOUT = 60  # Timeout for artifact execution (seconds)


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Sandbox Reporter: Analyzes artifact behavior in a sandboxed environment."
    )
    parser.add_argument("artifact", help="The path to the artifact to analyze.")
    parser.add_argument(
        "--timeout",
        type=int,
        default=TIMEOUT,
        help="Timeout in seconds for artifact execution (default: {})".format(TIMEOUT),
    )
    parser.add_argument(
        "--report",
        type=str,
        default=REPORT_FILE,
        help="Path to the report file (default: {})".format(REPORT_FILE),
    )
    return parser


def calculate_hash(filepath):
    """
    Calculates the SHA256 hash of a file.

    Args:
        filepath (str): The path to the file.

    Returns:
        str: The SHA256 hash of the file, or None if an error occurred.
    """
    try:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as afile:
            buf = afile.read()
            hasher.update(buf)
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {filepath}: {e}")
        return None


def run_in_sandbox(artifact, timeout):
    """
    Runs the artifact in a Docker sandbox and collects behavior information.

    Args:
        artifact (str): Path to the artifact.
        timeout (int): Timeout in seconds for execution.

    Returns:
        tuple: (stdout, stderr, return_code, filesystem_changes) from the
        process, where filesystem_changes is the docker diff output
        collected before the container is removed. None if the
        container fails.
    """
    try:
        # Create the container with a restrictive security profile:
        # all capabilities dropped, a non-root user, a read-only root
        # filesystem with a tmpfs scratch area, and the artifact
        # mounted read-only.
        subprocess.run(
            [
                "docker",
                "create",
                "--name",
                CONTAINER_NAME,
                "--network",
                "none",  # Disable network access
                "--pids-limit", "100", #Limit pids
                "--memory", "256m", # Limit memory usage
                "--cpus", "0.5", # limit CPU usage
                "--cap-drop", "ALL",
                "--user", SANDBOX_USER,
                "--read-only",
                "--tmpfs", "/tmp",
                "-v",
                f"{os.path.abspath(artifact)}:/artifact:ro", # mount the artifact read-only
                SANDBOX_IMAGE,
                "tail", "-f", "/dev/null" # Keep container running
            ],
            check=True,  # Raise exception on non-zero exit code
            capture_output=True,
            text=True
        )
    except FileNotFoundError:
        logging.error("Docker is unavailable: the docker binary was not found.")
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Error creating container: {e.stderr}")
        return None

    try:
        subprocess.run(
            [
                "docker",
                "start",
                CONTAINER_NAME,
            ],
            check=True,  # Raise exception on non-zero exit code
            capture_output=True,
            text=True
        )
    except FileNotFoundError:
        logging.error("Docker is unavailable: the docker binary was not found.")
        cleanup_container()
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Error starting container: {e.stderr}")
        cleanup_container()
        return None

    try:
        # Execute the artifact inside the container. No -it flags: the
        # process runs with piped output and no terminal attached.
        cmd = ["docker", "exec", "--user", SANDBOX_USER, CONTAINER_NAME, "bash", "-c", f"timeout {timeout} /artifact"]
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Wait for the process to complete with a timeout
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            logging.warning("Artifact execution timed out.")


        return_code = process.returncode

        # Record filesystem modifications inside the container before
        # cleanup removes it.
        try:
            diff_result = subprocess.run(
                ["docker", "diff", CONTAINER_NAME],
                capture_output=True,
                text=True,
                check=False
            )
            filesystem_changes = diff_result.stdout or ""
        except FileNotFoundError:
            logging.error("Docker is unavailable: the docker binary was not found.")
            filesystem_changes = ""

        return stdout, stderr, return_code, filesystem_changes

    except FileNotFoundError:
        logging.error("Docker is unavailable: the docker binary was not found.")
        return None

    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing artifact: {e}")
        return None

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

    finally:
        cleanup_container()

def cleanup_container():
    """
    Stops and removes the Docker container.
    """
    try:
        subprocess.run(["docker", "stop", CONTAINER_NAME], capture_output=True, text=True, check=False)  # Ignore errors if it's not running
        subprocess.run(["docker", "rm", CONTAINER_NAME], capture_output=True, text=True, check=False)   # Ignore errors if it doesn't exist
    except Exception as e:
        logging.error(f"Error cleaning up container: {e}")


def analyze_behavior(stdout, stderr, return_code, artifact_path):
    """
    Analyzes the output of the artifact execution and flags potentially malicious behavior.

    Args:
        stdout (str): The standard output of the artifact execution.
        stderr (str): The standard error of the artifact execution.
        return_code (int): The return code of the artifact execution.
        artifact_path (str): The path to the artifact.

    Returns:
        list: A list of strings indicating potential malicious behavior.
    """
    indicators = []

    # Check for suspicious system calls (example: using hardcoded paths or creating files in /tmp)
    if "rm -rf /" in stdout or "rm -rf /" in stderr:
        indicators.append("Attempted to delete the entire file system (rm -rf /)")

    # Network activity is not observed: the container runs with
    # networking disabled, so there is no network activity to check.

    # Check for file system modifications (example: creating executable files)
    if "chmod +x" in stdout or "chmod +x" in stderr:
        indicators.append("Attempted to change file permissions to executable.")

    if return_code != 0:
        indicators.append(f"Non-zero return code: {return_code}")

    if len(stdout) > 10000:
        indicators.append(f"Excessive stdout: possible buffer overflow exploit")

    if len(stderr) > 10000:
        indicators.append(f"Excessive stderr: possible error loop")

    if os.access(artifact_path, os.X_OK):
      indicators.append("The artifact is executable.")


    return indicators


def generate_report(artifact, hash_value, stdout, stderr, indicators, report_file, timeout, filesystem_changes=""):
    """
    Generates a report summarizing the artifact's behavior.

    Args:
        artifact (str): The path to the artifact.
        hash_value (str): The SHA256 hash of the artifact.
        stdout (str): The standard output of the artifact execution.
        stderr (str): The standard error of the artifact execution.
        indicators (list): A list of strings indicating potential malicious behavior.
        report_file (str): The path to the report file.
    """
    try:
        with open(report_file, "w") as f:
            f.write("Artifact Analysis Report\n")
            f.write("-------------------------\n")
            f.write(f"Artifact: {artifact}\n")
            f.write(f"SHA256 Hash: {hash_value}\n")
            f.write(f"Timeout: {timeout}\n")
            f.write("\n")
            f.write("Execution Output (stdout):\n")
            f.write(stdout)
            f.write("\n")
            f.write("Execution Output (stderr):\n")
            f.write(stderr)
            f.write("\n")
            f.write("Filesystem Modifications (docker diff, collected before cleanup):\n")
            if filesystem_changes.strip():
                f.write(filesystem_changes)
                if not filesystem_changes.endswith("\n"):
                    f.write("\n")
            else:
                f.write("No filesystem modifications recorded.\n")
            f.write("\n")
            f.write("Collection Limits:\n")
            f.write("No syscall trace is collected.\n")
            f.write("Network activity is not observed because the container runs with networking disabled.\n")
            f.write("\n")
            f.write("Potential Malicious Behavior:\n")
            if indicators:
                for indicator in indicators:
                    f.write(f"- {indicator}\n")
            else:
                f.write("No suspicious behavior detected.\n")

        logging.info(f"Report generated: {report_file}")

    except Exception as e:
        logging.error(f"Error generating report: {e}")


def main():
    """
    Main function of the script.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation
    if not os.path.exists(args.artifact):
        logging.error(f"Artifact not found: {args.artifact}")
        sys.exit(1)

    if not os.path.isfile(args.artifact):
        logging.error(f"Not a file: {args.artifact}")
        sys.exit(1)

    if args.timeout <= 0:
        logging.error("Timeout must be a positive integer.")
        sys.exit(1)

    if os.path.realpath(args.report) == os.path.realpath(args.artifact):
        logging.error("Report path must not be the artifact itself.")
        sys.exit(1)

    if shutil.which("docker") is None:
        logging.error("Docker is unavailable: the docker binary was not found on PATH.")
        sys.exit(1)

    # Calculate the hash of the artifact
    hash_value = calculate_hash(args.artifact)
    if not hash_value:
        sys.exit(1)

    # Run the artifact in the sandbox
    logging.info(f"Running artifact {args.artifact} in sandbox...")
    result = run_in_sandbox(args.artifact, args.timeout)

    if result is None:
        logging.error("Sandbox execution failed.")
        sys.exit(1)

    stdout, stderr, return_code, filesystem_changes = result

    # Analyze the artifact's behavior
    indicators = analyze_behavior(stdout, stderr, return_code, args.artifact)
    if filesystem_changes.strip():
        indicators.append("Filesystem modifications were recorded inside the container (see the docker diff section of this report).")

    # Generate the report
    generate_report(args.artifact, hash_value, stdout, stderr, indicators, args.report, args.timeout, filesystem_changes)

    logging.info("Artifact analysis complete.")


if __name__ == "__main__":
    main()