import unittest

from monitor import parse_trace


class Phase5BTraceTests(unittest.TestCase):
    def test_counts_positive_io_only_on_exact_fixture_paths(self):
        evidence = parse_trace([
            'read(3</var/lib/sentinelmesh-phase5b/decoys/agenda.txt>, ""..., 20) = 12',
            'read(3</var/lib/sentinelmesh-phase5b/decoys/agenda.txt>, ""..., 20) = 8',
            'read(3</var/lib/sentinelmesh-phase5b/decoys/agenda.txt>, "", 20) = 0',
            'read(3</var/lib/sentinelmesh-phase5b/decoys/agenda.txt.other>, ""..., 20) = 19',
            'write(4</var/lib/sentinelmesh-phase5b/copies/agenda.txt>, ""..., 20) = 20',
            'write(4</var/lib/sentinelmesh-phase5b/copies/agenda.txt>, ""..., 20) = -1 ENOSPC (No space)',
            'write(4</var/lib/sentinelmesh-phase5b/mock-autostart/fixture.marker>, ""..., 7) = 7',
        ])
        self.assertEqual(evidence["reads"], {"source/agenda.txt": 20})
        self.assertEqual(evidence["writes"], {"agenda.txt": 20, "marker": 7})

    def test_connect_failure_is_distinct_from_success_and_exec_is_attributed(self):
        evidence = parse_trace([
            'execve("/usr/bin/python3", [""...], 0x1 /* 3 vars */) = 0',
            'execve("/bogus", [""...], 0x1 /* 3 vars */) = -1 ENOENT (No such file)',
            'connect(3<TCP:[1234]>, {sa_family=AF_INET, sin_port=htons(41001), '
            'sin_addr=inet_addr("127.0.0.1")}, 16) = 0',
            'connect(3<TCP:[1235]>, {sa_family=AF_INET, sin_port=htons(41002), '
            'sin_addr=inet_addr("192.0.2.20")}, 16) = -1 ECONNREFUSED (Connection refused)',
        ])
        self.assertEqual(evidence["executables"], ["/usr/bin/python3"])
        self.assertEqual(evidence["connects"], [
            {"host": "127.0.0.1", "port": 41001, "result": "0"},
            {"host": "192.0.2.20", "port": 41002, "result": "-1 ECONNREFUSED"},
        ])
        self.assertNotIn("completed_transfer_bytes", evidence)
