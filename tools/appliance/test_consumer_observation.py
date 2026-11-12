"""Synthetic DOM observations only: no browser, VM, HTTP or task dispatch."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('consumer', Path(__file__).with_name('consumer.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)
PROJECT = 'http://127.0.0.1:7788/console/project?projectId=retained-project'


def page(*, ready='complete', control=False, refresh=None, heading='Preparing and checking the fix.', message='Recorded state', url=PROJECT):
    return {'ready': ready, 'expectedControl': control, 'refresh': refresh, 'heading': heading, 'message': message, 'url': url}


class Observation(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.sleeps = []

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def observe(self, pages, deadline=10, credential=None):
        read = Mock(side_effect=pages)
        with patch.object(app.time, 'monotonic', side_effect=lambda: self.now), patch.object(app.time, 'sleep', side_effect=self.sleep):
            result = app.wait_for_console_control(read, PROJECT, deadline, credential)
        return result, read

    def test_active_page_waits_for_ui_meta_refresh_without_reloading(self):
        expected = page(control=True, heading='Review the checked change.')
        result, read = self.observe([page(refresh='2'), expected])
        self.assertEqual(result, expected)
        self.assertEqual(read.call_count, 2)
        self.assertEqual(self.sleeps, [2])

    def test_delayed_document_or_empty_dom_does_not_become_a_failed_view(self):
        result, read = self.observe([page(ready='loading', heading='The demo needs attention.'),
                                     page(heading='', message=''), page(control=True)])
        self.assertTrue(result['expectedControl'])
        self.assertEqual(read.call_count, 3)
        self.assertEqual(self.sleeps, [2, 2])

    def test_expected_control_is_accepted_from_the_same_complete_snapshot(self):
        result, read = self.observe([page(control=True, heading='Ready to prepare the fix.')])
        self.assertTrue(result['expectedControl'])
        read.assert_called_once()
        self.assertEqual(self.sleeps, [])

    def test_complete_failed_or_held_view_stops_early_and_redacts_diagnostics(self):
        secret = '1' * 64
        for heading in ('The demo needs attention.', 'The demo worker is paused.', 'This demo needs reconciliation.'):
            with self.subTest(heading=heading):
                read = Mock(return_value=page(heading=heading, message='Retained failure ' + secret))
                with patch.object(app.time, 'monotonic', return_value=0), patch.object(app.time, 'sleep') as sleep, \
                     self.assertRaisesRegex(RuntimeError, 'held/failed.*no action retried') as caught:
                    app.wait_for_console_control(read, PROJECT, 600, secret)
                read.assert_called_once(); sleep.assert_not_called()
                self.assertIn(heading, str(caught.exception)); self.assertNotIn(secret, str(caught.exception))
        wrong_project = page(control=True, url=PROJECT.replace('retained-project', 'another-project'))
        with self.assertRaisesRegex(RuntimeError, 'another/unexpected page'):
            self.observe([wrong_project])

    def test_active_timeout_keeps_original_deadline_without_an_extra_action(self):
        read = Mock(return_value=page(refresh='2'))
        with patch.object(app.time, 'monotonic', side_effect=lambda: self.now), patch.object(app.time, 'sleep', side_effect=self.sleep), \
             self.assertRaisesRegex(RuntimeError, 'not observed before deadline.*no action retried'):
            app.wait_for_console_control(read, PROJECT, 3)
        self.assertEqual(read.call_count, 2)
        self.assertEqual(self.sleeps, [2, 1])


if __name__ == '__main__': unittest.main()
