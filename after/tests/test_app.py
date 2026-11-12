import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app import create_app, make_token, read_token, hash_password, check_password  # noqa: E402


class Client:
    def __init__(self, app=None):
        self.app = app or create_app(secret="test-secret")
        self.token = None

    def call(self, method, path, data=None, token="default", raw=None):
        raw = raw if raw is not None else (json.dumps(data).encode() if data is not None else b"")
        env = {"REQUEST_METHOD": method, "PATH_INFO": path, "CONTENT_LENGTH": str(len(raw)),
               "wsgi.input": io.BytesIO(raw)}
        token = self.token if token == "default" else token
        if token:
            env["HTTP_AUTHORIZATION"] = "Bearer " + token
        out = {}
        body = b"".join(self.app(env, lambda s, h: out.update(status=s)))
        return int(out["status"][:3]), json.loads(body)

    def signup(self, name="ana", password="correct-horse"):
        self.call("POST", "/register", {"name": name, "password": password}, token=None)
        _, res = self.call("POST", "/login", {"name": name, "password": password}, token=None)
        self.token = res["token"]


class AuthTests(unittest.TestCase):
    def test_register_login_roundtrip(self):
        c = Client()
        self.assertEqual(c.call("POST", "/register", {"name": "ana", "password": "correct-horse"}, token=None)[0], 201)
        status, res = c.call("POST", "/login", {"name": "ana", "password": "correct-horse"}, token=None)
        self.assertEqual(status, 200)
        self.assertIn("token", res)

    def test_wrong_password_is_401(self):
        c = Client()
        c.signup()
        self.assertEqual(c.call("POST", "/login", {"name": "ana", "password": "nope-nope"}, token=None)[0], 401)

    def test_duplicate_and_short_password(self):
        c = Client()
        c.signup()
        self.assertEqual(c.call("POST", "/register", {"name": "ana", "password": "another-pass"}, token=None)[0], 409)
        self.assertEqual(c.call("POST", "/register", {"name": "bob", "password": "short"}, token=None)[0], 400)

    def test_sql_injection_does_not_log_in(self):
        c = Client()
        c.signup()
        status, _ = c.call("POST", "/login", {"name": "ana' --", "password": "x' OR '1'='1"}, token=None)
        self.assertEqual(status, 401)

    def test_missing_or_forged_token_is_401(self):
        c = Client()
        self.assertEqual(c.call("GET", "/tasks", token=None)[0], 401)
        self.assertEqual(c.call("GET", "/tasks", token="YW5h")[0], 401)  # old base64("ana") token
        self.assertEqual(c.call("GET", "/tasks", token="ana|9999999999|deadbeef")[0], 401)

    def test_expired_token_rejected(self):
        tok = make_token("s", "ana", now=1000)
        self.assertEqual(read_token("s", tok, now=1000 + 10), "ana")
        self.assertIsNone(read_token("s", tok, now=1000 + 7200))

    def test_password_hash_not_plaintext(self):
        stored = hash_password("hunter2hunter2")
        self.assertNotIn("hunter2", stored)
        self.assertTrue(check_password("hunter2hunter2", stored))
        self.assertFalse(check_password("other", stored))


class TaskTests(unittest.TestCase):
    def setUp(self):
        self.c = Client()
        self.c.signup()

    def test_create_list_complete_delete(self):
        status, res = self.c.call("POST", "/tasks", {"title": "Buy milk"})
        self.assertEqual(status, 201)
        tid = res["id"]
        self.assertEqual(self.c.call("GET", "/tasks")[1], [{"id": tid, "title": "Buy milk", "done": False}])
        self.assertEqual(self.c.call("POST", f"/tasks/{tid}")[0], 200)
        self.assertTrue(self.c.call("GET", "/tasks")[1][0]["done"])
        self.assertEqual(self.c.call("DELETE", f"/tasks/{tid}")[0], 200)
        self.assertEqual(self.c.call("GET", "/tasks")[1], [])

    def test_complete_hits_the_right_task(self):  # regression: old code did id + 1
        a = self.c.call("POST", "/tasks", {"title": "A"})[1]["id"]
        self.c.call("POST", "/tasks", {"title": "B"})
        self.c.call("POST", f"/tasks/{a}")
        done = {t["title"]: t["done"] for t in self.c.call("GET", "/tasks")[1]}
        self.assertEqual(done, {"A": True, "B": False})

    def test_users_cannot_see_or_touch_each_others_tasks(self):
        tid = self.c.call("POST", "/tasks", {"title": "private"})[1]["id"]
        other = Client(self.c.app)  # same database
        other.signup("bob", "bobs-password")
        self.assertEqual(other.call("GET", "/tasks")[1], [])
        self.assertEqual(other.call("DELETE", f"/tasks/{tid}")[0], 404)
        self.assertEqual(other.call("POST", f"/tasks/{tid}")[0], 404)
        self.assertEqual(len(self.c.call("GET", "/tasks")[1]), 1)

    def test_validation(self):
        self.assertEqual(self.c.call("POST", "/tasks", {"title": "   "})[0], 400)
        self.assertEqual(self.c.call("POST", "/tasks", {"title": "x" * 500})[0], 400)
        self.assertEqual(self.c.call("POST", "/tasks", raw=b"{not json")[0], 400)
        self.assertEqual(self.c.call("POST", "/tasks/abc")[0], 400)
        self.assertEqual(self.c.call("GET", "/nothing")[0], 404)


class LimitTests(unittest.TestCase):
    def test_oversized_body_rejected(self):
        c = Client()
        self.assertEqual(c.call("POST", "/register", token=None, raw=b"{" + b" " * 20000 + b"}")[0], 413)

    def test_login_lockout_after_repeated_failures(self):
        c = Client()
        c.signup()
        for _ in range(5):
            self.assertEqual(c.call("POST", "/login", {"name": "ana", "password": "wrong-pass"}, token=None)[0], 401)
        # even the right password is refused while locked
        self.assertEqual(c.call("POST", "/login", {"name": "ana", "password": "correct-horse"}, token=None)[0], 429)
        # other users are not affected
        c.signup("bob", "bobs-password")
        self.assertEqual(c.call("POST", "/login", {"name": "bob", "password": "bobs-password"}, token=None)[0], 200)


class ConfigTests(unittest.TestCase):
    def test_secret_required(self):
        os.environ.pop("TASKTRACK_SECRET", None)
        with self.assertRaises(RuntimeError):
            create_app()


if __name__ == "__main__":
    unittest.main()
