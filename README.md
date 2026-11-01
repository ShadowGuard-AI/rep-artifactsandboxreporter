# rep-ArtifactSandboxReporter
A command-line tool that submits a software artifact to a lightweight, local sandbox environment (Docker containers) and monitors its behavior. It collects the artifact's printed output, its return code, and its file system modifications (recorded with docker diff before the container is removed), then generates a simple report summarizing the artifact's actions and flagging potentially malicious behavior based on pre-defined rules. No syscall trace is collected. Network activity is not observed because the container runs with networking disabled.

Execution conditions inside the sandbox, stated plainly: the artifact runs as a non-root user (65534:65534) with all Linux capabilities dropped (cap drop ALL). The artifact is mounted read-only, so the sandbox cannot modify the original file. The container root filesystem is read-only, with a tmpfs scratch area at /tmp. Networking is disabled. Resource limits apply (pids limit 100, memory 256m, cpus 0.5). The image is pinned to the specific tag ubuntu:22.04 instead of the mutable latest tag.

The report path (--report) must not be the artifact itself; such a run is refused with exit code 1. If the docker binary is not available, the run ends with exit code 1 and a clear docker unavailable message. - Focused on Automates the process of collecting and evaluating the reputation of digital artifacts (files, URLs, IPs) by querying public threat intelligence feeds and sandboxes.  It uses file hashing and URL analysis to provide a preliminary risk assessment.

## Install
`git clone https://github.com/ShadowGuardAI/rep-artifactsandboxreporter`

## Usage
`./rep-artifactsandboxreporter [params]`

## Parameters
- `-h`: Show help message and exit
- `--timeout`: Timeout in seconds for artifact execution.
- `--report`: Path to the report file. It must not be the artifact itself.

## License
Copyright (c) ShadowGuardAI
