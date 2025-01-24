# tests/run_tests.py

import unittest

if __name__ == '__main__':
    loader = unittest.TestLoader()
    start_dir = './'
    suite = loader.discover(start_dir, pattern='test_*.py')
    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
