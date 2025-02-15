import subprocess

# Get the list of packages without indirect dependencies
result = subprocess.run(["pip", "list", "--not-required"], capture_output=True, text=True)
lines = result.stdout.splitlines()[2:]  # Skip headers

with open("requirements-new.txt", "w") as f:
    for line in lines:
        package = line.split()[0]  # Extract package name
        version_result = subprocess.run(["pip", "show", package], capture_output=True, text=True)
        version = None
        for show_line in version_result.stdout.splitlines():
            if show_line.startswith("Version:"):
                version = show_line.split(":")[1].strip()
                break
        if version:
            f.write(f"{package}=={version}\n")