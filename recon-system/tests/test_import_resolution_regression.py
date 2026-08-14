"""Regression tests for import resolution and compilation pipeline.

These tests verify that the pipeline correctly handles import graphs,
transitive dependencies, and proper file status classification.
"""

import unittest
from unittest import mock
import json
import tempfile
import os

from recon import pipeline, solc_manager


class TestImportResolutionRegression(unittest.TestCase):
    
    def _get_metadata(self, output_dir):
        """Read metadata.json from output directory."""
        metadata_path = os.path.join(output_dir, "metadata.json")
        with open(metadata_path, "r") as f:
            return json.load(f)

    def test_transitive_import_closure_in_compilation_unit(self):
        """Test that A -> B -> C transitive import closure is compiled together."""
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./B.sol";\ncontract A {}',
            "B.sol": 'pragma solidity ^0.8.20;\nimport "./C.sol";\ncontract B {}',
            "C.sol": 'pragma solidity ^0.8.20;\ncontract C {}',
        }
        
        # Mock solc output
        fake_output = json.dumps({
            "errors": [],
            "sources": {
                "A.sol": {"ast": {"nodeType": "SourceUnit"}},
                "B.sol": {"ast": {"nodeType": "SourceUnit"}},
                "C.sol": {"ast": {"nodeType": "SourceUnit"}},
            },
        })
        fake_proc = mock.Mock(returncode=0, stdout=fake_output, stderr="")
        
        with mock.patch("subprocess.run", return_value=fake_proc), \
             tempfile.TemporaryDirectory() as tmpdir:
            
            # Create all files
            for name, content in sources.items():
                with open(os.path.join(tmpdir, name), "w") as f:
                    f.write(content)
            
            # Run pipeline
            pipeline.run(
                repo_root=tmpdir,
                output_dir=tmpdir,
                offline=True,  # Disable npm installs
                timeout_seconds=60,
            )
            
            # Read metadata
            metadata = self._get_metadata(tmpdir)
            
            # Verify all files were analyzed (not failed)
            self.assertEqual(len(metadata["files_analyzed"]), 3)
            self.assertIn("A.sol", metadata["files_analyzed"])
            self.assertIn("B.sol", metadata["files_analyzed"])
            self.assertIn("C.sol", metadata["files_analyzed"])
            self.assertEqual(len(metadata["files_failed"]), 0)

    def test_missing_import_blocks_compilation(self):
        """Test that missing imports are properly classified as failed."""
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./Missing.sol";\ncontract A {}',
        }
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create only A.sol
            with open(os.path.join(tmpdir, "A.sol"), "w") as f:
                f.write(sources["A.sol"])
            
            # Run pipeline
            pipeline.run(
                repo_root=tmpdir,
                output_dir=tmpdir,
                offline=True,
                timeout_seconds=60,
            )
            
            # Read metadata
            metadata = self._get_metadata(tmpdir)
            
            # Verify A.sol is in failed files, not analyzed
            self.assertIn("A.sol", metadata["files_failed"])
            self.assertNotIn("A.sol", metadata["files_analyzed"])

    def test_partial_compilation_classification(self):
        """Test that files with AST errors are properly classified."""
        sources = {
            "A.sol": 'pragma solidity ^0.8.20;\nimport "./B.sol";\ncontract A {}',
            "B.sol": 'pragma solidity ^0.8.20;\ncontract B { syntax error }',  # Invalid syntax
        }
        
        # Mock solc output with error for B.sol
        fake_output = json.dumps({
            "errors": [
                {
                    "severity": "error",
                    "message": "ParserError: Expected token Semicolon got 'EOF'",
                    "sourceLocation": {"file": "B.sol"}
                }
            ],
            "sources": {
                "A.sol": {"ast": {"nodeType": "SourceUnit"}},
                "B.sol": {},  # No AST for B.sol
            },
        })
        fake_proc = mock.Mock(returncode=0, stdout=fake_output, stderr="")
        
        with mock.patch("subprocess.run", return_value=fake_proc), \
             tempfile.TemporaryDirectory() as tmpdir:
            
            # Create both files
            for name, content in sources.items():
                with open(os.path.join(tmpdir, name), "w") as f:
                    f.write(content)
            
            # Run pipeline
            pipeline.run(
                repo_root=tmpdir,
                output_dir=tmpdir,
                offline=True,
                timeout_seconds=60,
            )
            
            # Read metadata
            metadata = self._get_metadata(tmpdir)
            
            # Verify A.sol analyzed, B.sol failed
            self.assertIn("A.sol", metadata["files_analyzed"])
            self.assertIn("B.sol", metadata["files_failed"])
            self.assertEqual(len(metadata["files_analyzed"]), 1)
            self.assertEqual(len(metadata["files_failed"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)