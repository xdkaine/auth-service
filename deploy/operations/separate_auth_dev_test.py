import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('move_auth',Path(__file__).with_name('separate-auth-dev.py'))
move=importlib.util.module_from_spec(spec);spec.loader.exec_module(move)
class CutoverSafety(unittest.TestCase):
 def test_prepare_cannot_overwrite_new_service_with_self_alias(self):
  alias={'spec':{'type':'ExternalName','externalName':'auth.auth-dev.svc.cluster.local'}}
  with patch.object(move,'kub',return_value=alias),patch.object(move,'apply') as apply:
   with self.assertRaisesRegex(RuntimeError,'prepare cannot run after cutover'):move.prepare()
   apply.assert_not_called()
if __name__=='__main__':unittest.main()
