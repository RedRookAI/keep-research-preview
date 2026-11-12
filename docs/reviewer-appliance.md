# Use the Linux x64 reviewer appliance

The **0.0.30-preview.1** appliance supplies Keep, Node, Git, the sandbox helper and the generation engine in a Debian 13 guest. Its webhook sample uses two authored responses to produce an edit, four checks and a proposal you can approve or veto. It needs no model account.

## Host requirements and download

Use Linux x64 with Python 3.8+, OpenSSH, `qemu-system-x86_64`, `qemu-img` and existing read/write KVM access. The tested profile uses QEMU 8.2.2 and `pc-q35-8.2`, with 2 vCPU, 2 GiB RAM and an 8 GiB virtual guest disk. ARM64 and other host/hypervisor profiles remain unqualified.

Allow space for the download, roughly 2 GB base image and each instance's writable overlay. First start requires **8 GiB of free host storage after extraction**, in addition to the bundle already on disk. Host Node/npm/Rust are unnecessary; the launcher leaves host tools and policy unchanged.

https://github.com/RedRookAI/keep-research-preview/releases/tag/keep-reviewer-2026-11-12.4

Download the appliance archive and its matching `.sha256` file from that release. The bundle contains a separate `SHA256SUMS` file for its extracted contents.

The release includes the exact consumer receipt, matching sources and checksums. Version 0.0.30 checks both staged and committed changes against the reviewed proposal before merge. The build recipe is under `tools/appliance`.

## Start your instance

Verify the published checksum, extract the bundle and keep its directory in place. Choose a new private instance directory with a short path so its QMP socket fits the Linux path limit.

```sh
python3 keep-appliance.py check
python3 keep-appliance.py start /your/private/keep-instance --port 7788 --ssh-port 2222
python3 keep-appliance.py status /your/private/keep-instance
```

Both ports must be free. Startup creates private instance and guest SSH keys, then boots with the sample stopped. Occupied ports or unfamiliar state produce a correction message and preserve existing work.

## Try the browser sample

```sh
python3 keep-appliance.py sample-start /your/private/keep-instance
python3 keep-appliance.py credential /your/private/keep-instance
```

Open the reported address and enter the credential. The guest and host use the same literal `127.0.0.1` port to preserve the browser origin.

On a remote host, add an SSH tunnel from your browser's computer using that same local port. For example, forward your computer's `127.0.0.1:7788` to the appliance host's `127.0.0.1:7788`, then open it in your own browser.

You can also open the public hosted demo without signing in:

https://keep-demo.redrook.ai/console

Choose **Start demo**, then **Prepare the fix**. Inspect the webhook diff and four checks, approve or veto the proposal, then choose **Download evidence**.

Appliance approval retains the reviewed workspace and leaves the source repository unchanged. Both decisions remain available with their evidence after reopening the sample.

```sh
python3 keep-appliance.py sample-stop /your/private/keep-instance
python3 keep-appliance.py sample-start /your/private/keep-instance
```

Restart retains the same jobs, decisions and exports. Inspect interrupted work before resuming it.

## Distribution records

The manifest identifies the guest runtime, host assembly and component hashes. The guest runtime's `source-support.tar.gz` contains its matching source. `HOST_SOURCE.tar.gz` contains the source for the bundled host tools and qualifier. Guest support includes installed source versions, Built-Using fields, notices, component identities and file checksums. The bundle also carries the pinned Bubblewrap source and build recipe.

The published Debian source companion contains all 289 required source/version pairs, including the Debian patches in the guest inventory. The release qualification records the exact image and clean-consumer observations.

## Set up your own repository

Open the guest shell:

```sh
python3 keep-appliance.py shell /your/private/keep-instance
```

Start device login and follow its browser instructions:

```sh
keep-engine login --device-auth
```

Use `keep instance init` with your repository, checker, engine/model and limits. Follow the packaged [Codex project](codex-project.md) and [local-instance](local-instance.md) guides. Login credentials stay in your private instance. Boot and sample startup make no model calls. Optional OpenClaw uses its own supported patched Node 24 runtime.

Stop the sample before starting a personal instance on the same console port. After starting that instance inside the guest, open a foreground SSH forward from the appliance host. This example uses the default ports:

```sh
APPLIANCE_STATE=/your/private/keep-instance
(
  cd -- "$APPLIANCE_STATE" || exit
  exec ssh -F /dev/null -i owner-key \
    -o IdentitiesOnly=yes -o ForwardAgent=no \
    -o UserKnownHostsFile=known-hosts -o StrictHostKeyChecking=yes \
    -o ExitOnForwardFailure=yes -N \
    -L 127.0.0.1:7788:127.0.0.1:7788 -p 2222 keep@127.0.0.1
)
```

Relative credential paths keep `known-hosts` usable when the instance directory contains spaces. Keep this terminal open while using the console. For a remote host, add the client-to-host tunnel described above. Enter the personal instance's gateway credential; it differs from the sample invitation and model login. Ctrl-C closes the forward while leaving the guest and state running.

## Stop and remove

```sh
python3 keep-appliance.py sample-stop /your/private/keep-instance
python3 keep-appliance.py stop /your/private/keep-instance
python3 keep-appliance.py status /your/private/keep-instance
```

Stop reports whether graceful shutdown was confirmed and lists unresolved sample work when available. If shutdown or process identity is uncertain, inspect the retained private logs and state.

Once status confirms that the guest and tunnel have stopped, you can remove the owned instance directory to erase its overlay, keys and state. Retain it to keep your work and login. Keep the bundle while any instance uses its base image.
