import tempfile
import unittest
from pathlib import Path

from whitecell.state import SessionState


class StateMemoryTests(unittest.TestCase):
    def test_helper_learning_persists_to_local_brain_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            storage_dir = Path(temp_dir)

            state = SessionState()
            state.initialize_brain(agent_name="agent-alpha", local_dir=storage_dir)
            state.learn_from_helper(
                "alpha",
                "Observed suspicious registry persistence technique",
                ["persistence", "registry-monitoring"],
            )

            reloaded = SessionState()
            reloaded.initialize_brain(agent_name="agent-alpha", local_dir=storage_dir)

            memories = reloaded.get_helper_memories("alpha")
            self.assertEqual(len(memories), 1)
            self.assertIn("persistence", memories[0]["techniques"])
            self.assertIn("registry-monitoring", reloaded.get_collective_techniques())


if __name__ == "__main__":
    unittest.main()
