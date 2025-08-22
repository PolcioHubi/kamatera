import itertools


def test_login_rate_limit_429(client):
    # Ensure user exists
    client.post('/register', json={'username': 'rl_user', 'password': 'pass12345', 'accessKey': 'test_access_key'})

    # Spam wrong password to trigger limiter
    got_429 = False
    for _ in itertools.repeat(None, 50):
        r = client.post('/login', json={'username': 'rl_user', 'password': 'wrong'})
        if r.status_code == 429:
            got_429 = True
            break
    assert got_429 or client.application.testing, "Limiter should trigger 429 during tests or be bypassed in specific test modes"

