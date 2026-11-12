# Use the Linux x64 reviewer appliance

The appliance carries Keep, its Node runtime, Git, the fixed sandbox helper and the bundled generation engine in a Debian13 guest. The account-free sample lets you submit a goal, inspect real edits and checks, veto the proposal and download its evidence. It uses two scripted responses.

This package targets Linux x64 with QEMU/KVM and the pc-q35-8.2 machine. QEMU8.2.2 was used for the profile proof. Your host needs Python3.8 or later, OpenSSH, qemu-system-x86_64, qemu-img, existing read/write KVM access and at least8GiB free storage. The guest uses2vCPU and2GiB RAM. Host Node/npm/Rust are unnecessary. The launcher installs no host tools or policy.

The source recipe is under tools/appliance. A shipping download is available only after its exact artifact passes the clean-consumer check and the release record supplies its URL and checksum. The earlier KC110 proof identifies the supported baseline; it does not qualify a new image by itself.

## Start your instance

Verify the published download checksum, extract the bundle and keep that directory in place. Each instance has its own private writable directory and overlay. Choose a short path for that directory so the private QMP socket fits the Linux path limit.

```sh
python3 keep-appliance.py check
python3 keep-appliance.py start /your/private/keep-instance --port 7788 --ssh-port 2222
python3 keep-appliance.py status /your/private/keep-instance
```

The ports must be free. Startup creates a private instance key and fresh guest SSH host keys. It starts the guest with the sample stopped. An occupied port or unfamiliar instance state produces a correction message and preserves existing work.

## Try the browser sample

```sh
python3 keep-appliance.py sample-start /your/private/keep-instance
python3 keep-appliance.py credential /your/private/keep-instance
```

Sample startup checks the console through the owned SSH forward before reporting its local browser address. On a host with a browser, open that reported address and enter the credential. The guest and host use the same literal127.0.0.1 port to preserve the browser origin.

For a remote host, make an additional SSH tunnel from your browser's computer to the host using the same local port. For example, forward your computer's127.0.0.1:7788 to the appliance host's127.0.0.1:7788. Open that address in your own browser. The separately hosted HTTPS demo is the direct browser option for a headless setup; its actual URL belongs in the published release instructions.

Choose **Submit a repository goal**, then **Submit goal**. Approve the displayed step to run the sample. Inspect the checked diff, choose **Veto proposal**, open the updated project and download the proposal evidence. The original sample repository remains unchanged after veto. Opening or refreshing the console does not submit another goal.

In this appliance sample, proposal approval retains the reviewed workspace and leaves the source repository unchanged. You can reopen either an approved or vetoed sample to inspect its retained decision and export.

```sh
python3 keep-appliance.py sample-stop /your/private/keep-instance
python3 keep-appliance.py sample-start /your/private/keep-instance
```

Restart reopens the same sample and its retained jobs. It preserves decisions and exports. If a job was interrupted, inspect its recorded state before resuming; startup does not reset the instance or create a replacement task.

## Set up your own repository

Open the guest shell when you want to configure a personal project:

```sh
python3 keep-appliance.py shell /your/private/keep-instance
```

Inside the guest, start the existing device login flow and follow its browser instructions:

```sh
keep-engine login --device-auth
```

Then use keep instance init with your repository, checker, engine/model and chosen limits, following the existing Codex project and local-instance guides carried in the package. Login and model credentials stay in your private instance. Boot and sample startup make no model calls. OpenClaw remains a separate optional client with its own supported patched Node24 runtime.

## Stop and remove

```sh
python3 keep-appliance.py sample-stop /your/private/keep-instance
python3 keep-appliance.py stop /your/private/keep-instance
python3 keep-appliance.py status /your/private/keep-instance
```

Stop requests graceful guest shutdown and reports whether it was confirmed. It also reports unresolved sample work when available. If shutdown or a process identity is uncertain, inspect the retained private logs and state before taking further action. The launcher leaves the instance directory intact.

Once status confirms that the owned guest and tunnel are stopped, you can remove that instance directory to remove its overlay, keys and state. Keep it when you want to retain work or personal login. Keep the bundle while any instance uses its base image. Other hypervisors and ARM64 remain outside this package's supported profile.
