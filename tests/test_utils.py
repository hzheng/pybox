# -*- coding: utf-8 -*-

"""
Test utilities.
"""

from pybox.utils import get_sha1, get_browser, user_of_email


def test_get_sha1(tmpdir):
    text_hash_pairs = [
        ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        ("1234567890", "01b307acba4f54f55aafc33bb06bbbf6ca803e9a"),
        ("1234567890\n", "12039d6dd9a7e27622301e935b6eefc78846802e"),
        ("abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    ]
    for text, hash_val in text_hash_pairs:
        f = tmpdir.join("tmp.txt")
        f.write(text)
        assert get_sha1(str(f)) == hash_val


def test_get_browser():
    browser = get_browser()
    browser.open("http://www.yahoo.com")
    assert browser.viewing_html()


def test_user_of_email():
    assert user_of_email("@gmail.com") is None
    assert user_of_email("gmail.com") is None
    assert user_of_email("bob@gmail") is None
    assert user_of_email("bob@gmail.com") == "bob"
