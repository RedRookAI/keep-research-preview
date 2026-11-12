"""Exercise the probe's private environment before it loads the guest runtime."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('consumer', Path(__file__).with_name('consumer.py'))
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)


class BoundaryEnvironment(unittest.TestCase):
    def test_inherited_environment_and_group_writable_umask_cannot_reach_fixture(self):
        node = shutil.which('node')
        self.assertIsNotNone(node)
        with tempfile.TemporaryDirectory(prefix='probe environment ') as temporary:
            prefix = consumer.APPROVAL_BOUNDARY_PROBE.split('const {createBrowserProjectFixture', 1)[0]
            helper = Path(__file__).resolve().parents[1] / 'reviewer_node_toolchain.mjs'
            prefix = prefix.replace("'/opt/keep/runtime/tools/reviewer_node_toolchain.mjs'", json.dumps(str(helper)))
            prefix = prefix.replace("'/home/keep/approval-boundary-'", json.dumps(temporary + '/probe-'))
            script = "process.umask(0o002);\n" + prefix + """
              const {statSync}=await import('node:fs');
              assert.deepEqual(Object.keys(process.env).sort(),['GIT_CONFIG_GLOBAL','GIT_CONFIG_NOSYSTEM',
                'GIT_TERMINAL_PROMPT','HOME','PATH','TMPDIR']);
              assert.equal(process.env.PATH,node.bin+':/usr/bin:/bin');
              assert.equal(process.cwd(),root);
              for(const path of [root,process.env.HOME,process.env.TMPDIR]) assert.equal(statSync(path).mode&0o777,0o700);
              writeFileSync(join(root,'private-file'),'private');
              assert.equal(statSync(join(root,'private-file')).mode&0o777,0o600);
              rmSync(root,{recursive:true,force:true});
            """
            subprocess.run([node, '--input-type=module', '-e', script], check=True, timeout=10,
                env={**os.environ, 'PATH': '/not-the-measured-node', 'HOME': temporary,
                     'TMPDIR': temporary, 'GITHUB_TOKEN': 'synthetic-must-not-reach-fixture'},
                capture_output=True, text=True)


if __name__ == '__main__': unittest.main()
