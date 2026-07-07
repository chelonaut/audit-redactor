from audit_redactor.detectors.base import EntityType
from audit_redactor.detectors.platform_identity import (
    KnownIdentityDetector,
    find_identity_usernames,
)


class TestFindIdentityUsernames:
    def test_finds_username_from_profile_url(self) -> None:
        assert find_identity_usernames(["See https://github.com/chelonaut for details."]) == {
            "chelonaut"
        }

    def test_finds_username_from_repo_url(self) -> None:
        assert find_identity_usernames(
            ["https://github.com/chelonaut/claude-news-aggregator-prompt"]
        ) == {"chelonaut"}

    def test_finds_username_from_query_string(self) -> None:
        assert find_identity_usernames(
            ["https://github.com/chelonaut/repo/commits?author=chelonaut"]
        ) == {"chelonaut"}

    def test_finds_username_from_ssh_remote(self) -> None:
        assert find_identity_usernames(["clone via git@github.com:chelonaut/repo.git"]) == {
            "chelonaut"
        }

    def test_bare_github_root_yields_nothing(self) -> None:
        assert find_identity_usernames(["https://github.com/"]) == set()

    def test_reserved_route_is_not_treated_as_a_username(self) -> None:
        assert find_identity_usernames(["https://github.com/settings", "https://github.com/marketplace"]) == set()

    def test_short_segment_below_min_length_is_ignored(self) -> None:
        assert find_identity_usernames(["https://github.com/ab"]) == set()

    def test_non_identity_host_is_ignored(self) -> None:
        assert find_identity_usernames(["https://example.com/chelonaut"]) == set()

    def test_aggregates_across_multiple_texts(self) -> None:
        found = find_identity_usernames(
            ["https://github.com/chelonaut", "unrelated text", "https://github.com/octocat/repo"]
        )
        assert found == {"chelonaut", "octocat"}

    def test_no_urls_yields_empty_set(self) -> None:
        assert find_identity_usernames(["just some plain prose, nothing linked"]) == set()


class TestKnownIdentityDetector:
    def test_detects_bare_occurrence(self) -> None:
        detector = KnownIdentityDetector({"chelonaut"})
        spans = detector.detect("chelonaut authored 4 days ago")
        assert len(spans) == 1
        assert spans[0].text == "chelonaut"
        assert spans[0].entity_type == EntityType.USERNAME_MENTION

    def test_no_match_returns_empty(self) -> None:
        detector = KnownIdentityDetector({"chelonaut"})
        assert detector.detect("nothing relevant here") == []

    def test_does_not_match_as_a_substring_of_a_longer_word(self) -> None:
        detector = KnownIdentityDetector({"art"})
        assert detector.detect("let's start the meeting") == []

    def test_matches_every_occurrence(self) -> None:
        detector = KnownIdentityDetector({"chelonaut"})
        spans = detector.detect("chelonaut here, and chelonaut again")
        assert len(spans) == 2

    def test_empty_username_set_matches_nothing(self) -> None:
        detector = KnownIdentityDetector(set())
        assert detector.detect("chelonaut authored this") == []
