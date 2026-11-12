"""Navigation custody controls with scripted browser observations; no browser or VM."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('consumer_navigation', Path(__file__).with_name('consumer.py'))
app = importlib.util.module_from_spec(spec); spec.loader.exec_module(app)
ORIGIN = 'http://127.0.0.1:7788'
PROJECT = ORIGIN + '/console/project?projectId=retained-project'


def page(url=PROJECT, document=101, ready='complete', link=''):
    return {'url': url, 'document': document, 'ready': ready, 'projectLink': link}


class ConsumerNavigation(unittest.TestCase):
    def observe(self, frames, **options):
        read = Mock(side_effect=frames)
        with patch.object(app.time, 'monotonic', return_value=0), patch.object(app.time, 'sleep') as sleep:
            result = app.wait_for_console_navigation(read, 100, 10, **options)
        return result, read, sleep

    def test_delayed_submit_waits_for_new_completed_project_document(self):
        frames = [page(ORIGIN + '/console', document=100),
                  page(ORIGIN + '/console/submit', ready='loading'), page()]
        result, read, sleep = self.observe(frames)
        self.assertEqual(result, (PROJECT, 'retained-project'))
        self.assertEqual(read.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_same_url_resume_and_recovery_require_a_new_document(self):
        for action in (None, '/console/resume'):
            with self.subTest(action=action):
                result, read, _ = self.observe([page(document=100), page()], project_url=PROJECT, action_path=action)
                self.assertEqual(result, (PROJECT, 'retained-project'))
                self.assertEqual(read.call_count, 2, 'pre-click document cannot confirm a dispatched action')

    def test_action_response_is_waited_for_before_its_retained_project_link(self):
        for action in ('/console/resume', '/console/merge'):
            with self.subTest(action=action):
                action_url = ORIGIN + action
                result, read, _ = self.observe([page(document=100), page(action_url, ready='loading'),
                                               page(action_url, link=PROJECT)], project_url=PROJECT, action_path=action)
                self.assertEqual(result, (action_url, 'retained-project'))
                self.assertEqual(read.call_count, 3)

    def test_completed_error_or_missing_project_response_refuses_without_retry(self):
        for response in [page(ORIGIN + '/console/submit'), page(ORIGIN + '/console'),
                         page(ORIGIN + '/console/project'), page(ORIGIN + '/console/project?projectId=')]:
            with self.subTest(url=response['url']), self.assertRaisesRegex(RuntimeError, 'unexpected/error page.*no submission or action retried'):
                self.observe([response])

    def test_other_project_origin_or_action_link_cannot_replace_retained_project(self):
        cases = [page(ORIGIN + '/console/project?projectId=another-project'),
                 page('https://elsewhere.invalid/console/project?projectId=retained-project'),
                 page(ORIGIN + '/console/merge', link=ORIGIN + '/console/project?projectId=another-project'),
                 page(ORIGIN + '/console/merge')]
        for response in cases:
            with self.subTest(response=response), self.assertRaises(RuntimeError):
                self.observe([response], project_url=PROJECT, action_path='/console/merge')

    def test_timeout_observes_once_and_never_retries_submission(self):
        read = Mock(return_value=page(document=100))
        with patch.object(app.time, 'monotonic', side_effect=[0, 1]), patch.object(app.time, 'sleep'), \
             self.assertRaisesRegex(RuntimeError, 'not confirmed before deadline.*no submission or action retried'):
            app.wait_for_console_navigation(read, 100, 0.5)
        self.assertEqual(read.call_count, 1)

    def test_project_query_must_be_one_unambiguous_identifier(self):
        for query in ('projectId=a&projectId=b', 'projectId=a&token=secret', 'other=a', 'projectId=a%22b'):
            with self.subTest(query=query):
                self.assertIsNone(app.console_project_id(ORIGIN + '/console/project?' + query))
        self.assertEqual(app.console_project_id(PROJECT), 'retained-project')

    def test_login_waits_for_delayed_new_completed_authenticated_landing(self):
        landing = ORIGIN + '/console'
        frames = [dict(page(landing, document=100), expectedControl=True),
                  dict(page(ORIGIN + '/console/login', ready='loading'), expectedControl=False),
                  dict(page(landing, ready='loading'), expectedControl=False),
                  dict(page(landing), expectedControl=True)]
        read = Mock(side_effect=frames)
        with patch.object(app.time, 'monotonic', return_value=0), patch.object(app.time, 'sleep') as sleep:
            result = app.wait_for_console_page(read, 100, 10, expected_url=landing, require_control=True)
        self.assertEqual(result, frames[-1])
        self.assertEqual(read.call_count, 4)
        self.assertEqual(sleep.call_count, 3)

    def test_completed_login_requires_authenticated_fixed_goal_control(self):
        landing = ORIGIN + '/console'
        read = Mock(return_value=dict(page(landing), expectedControl=False))
        with patch.object(app.time, 'monotonic', return_value=0), \
             self.assertRaisesRegex(RuntimeError, 'lacks its authenticated/expected control.*no action retried'):
            app.wait_for_console_page(read, 100, 10, expected_url=landing, require_control=True)
        self.assertEqual(read.call_count, 1)

    def test_login_completed_error_foreign_or_wrong_redirect_is_refused(self):
        landing = ORIGIN + '/console'
        for url in (ORIGIN + '/console/login', PROJECT, 'https://elsewhere.invalid/console', landing + '?token=secret'):
            with self.subTest(url=url), patch.object(app.time, 'monotonic', return_value=0), \
                 self.assertRaisesRegex(RuntimeError, 'unexpected/error route.*no action retried'):
                app.wait_for_console_page(lambda: dict(page(url), expectedControl=True), 100, 10,
                                          expected_url=landing, require_control=True)

    def test_login_timeout_only_observes_and_does_not_repeat_post(self):
        read = Mock(return_value=dict(page(ORIGIN + '/console', document=100), expectedControl=False))
        with patch.object(app.time, 'monotonic', side_effect=[0, 1]), patch.object(app.time, 'sleep'), \
             self.assertRaisesRegex(RuntimeError, 'not confirmed before deadline.*no action retried'):
            app.wait_for_console_page(read, 100, 0.5, expected_url=ORIGIN + '/console', require_control=True)
        self.assertEqual(read.call_count, 1)

    def test_explicit_project_and_recovery_form_navigation_wait_for_exact_new_page(self):
        for target in (PROJECT, ORIGIN + '/console/new', ORIGIN + '/console'):
            with self.subTest(target=target):
                frames = [page(target, document=100), page(target)]
                read = Mock(side_effect=frames)
                with patch.object(app.time, 'monotonic', return_value=0), patch.object(app.time, 'sleep'):
                    result = app.wait_for_console_page(read, 100, 10, expected_url=target)
                self.assertEqual(result['url'], target)
                self.assertEqual(read.call_count, 2)
        with patch.object(app.time, 'monotonic', return_value=0), self.assertRaises(RuntimeError):
            app.wait_for_console_page(lambda: page(ORIGIN + '/console/project?projectId=other'), 100, 10, expected_url=PROJECT)

    def test_failure_body_is_bounded_and_known_credentials_and_query_are_removed(self):
        secret = '1' * 64
        value = app.failure_diagnostics('http://user:password@127.0.0.1:7788/console/submit?token=' + secret,
                                        'Visible failure ' + secret + ' ' + 'a' * 64 + ' ' + 'x' * 9000, secret)
        self.assertEqual(value['urlWithoutQuery'], ORIGIN + '/console/submit')
        self.assertNotIn(secret, value['bodyText'])
        self.assertNotIn('a' * 64, value['bodyText'])
        self.assertIn('Visible failure', value['bodyText'])
        self.assertEqual(len(value['bodyText']), 8192)


if __name__ == '__main__': unittest.main()
