import fnmatch
from typing import Any

import regex as re

from . import schemas


def match_search_id(rule: schemas.Rule, event: dict[Any, Any], search_id: str):
    search_fields = rule.get_search_fields(search_id)
    if search_fields:
        return find_matches(event, search_fields)

    raise ValueError()


def check_pair(event: dict[Any, Any], key: str, value: schemas.Query) -> bool:
    """
    Checks to see if a given key and value from the rule are also in the event.
    Takes into consideration any value modifiers.

    :param event: dict, a single event from the event log
    :param key: str, given dict key
    :param value: str, given key value
    :return: bool, whether or not the match exists in the event
    """
    # Before we can apply modifiers and search properly, we need to check if there
    # is even a value to modify, so do the null checks first
    if value is None:
        return event.get(key) is None

    if key not in event:
        return False

    if isinstance(value, re.Pattern):
        return bool(value.match(str(event[key])))

    # Because by default sigma string matching is case insensitive, lower the event
    # string before comparing it. The value string is already lowercase.
    # TODO potential optimization by caching lowercased event fields
    return str(event[key]).lower() == value


def find_matches(
    event: dict, search: schemas.DetectionField, match_all: bool = False
) -> bool:
    """
    Matches the items in the rule to the event. Iterates through the sections and if there's a list it iterates
    through that. Uses checkPair to see if the items in the list/dictionary match items in the event log.

    :param event: dict, event read from the Sysmon log
    :param search: An object describing what sort of search to run
    :param match_all: A bool indicating if we want all fields in list to hit
    :return: bool, whether or not we found a match
    """
    if search.list_search:
        check = all if match_all else any
        return check(
            any(check_pair(event, event_key, field) for event_key in event)
            for field in search.list_search
        )

    for field in search.map_search:
        if find_matches_by_map(event, field):
            return True

    return False


def find_matches_by_map(event: dict[Any, Any], search: schemas.DetectionMap) -> bool:
    """
    :param event:
    :param search: a dict of fields to search. All must be satisfied.
    :return:
    """

    for field_name, (value, modifiers) in search:
        if not find_matches_by_map_entry(event, field_name, value, modifiers):
            return False

    return True


def find_matches_by_map_entry(
    event: dict,
    field_name: str,
    field_values: list[schemas.Query],
    modifiers: list[str],
) -> bool:
    """
    :param event: the event to search in
    :param field_name: A field in the event we want to search
    :param field_values: valid values or patterns for the field in question
    :return:
    """

    # Normally any of the values in field_values is acceptable, but the all modifier inverts that
    if "all" in modifiers:
        for permitted_value in field_values:
            if not check_pair(event, field_name, permitted_value):
                return False

        return True

    for permitted_value in field_values:
        if check_pair(event, field_name, permitted_value):
            return True

    return False


def analyze_x_of(
    rule: schemas.Rule,
    event: dict[Any, Any],
    count: int | None = None,
    selector: str | None = None,
) -> bool:
    """
    Analyzes the truth value of an 'x of' condition specified within the condition string of the rule.

    :param rule: Rule currently being applied
    :param event: event currently being scanned
    :param count: left side of the x of statement, either 1 or None (for all)
    :param selector: right side of the x of statement, a pattern or None (for all)
    :return: bool, truth value of 'x of' condition
    """

    # First we need to choose our set of fields based on our selector.
    matches: dict[str, schemas.DetectionField] = {}
    all_searches = rule.get_all_searches()

    if selector is None:  # None indicates all.
        matches = all_searches
    else:
        for search_id, search_fields in all_searches.items():
            if fnmatch.fnmatch(search_id, selector):
                matches[search_id] = search_fields

    match_all = False
    if count is None:
        match_all = True
        count = len(matches)

    permitted_misses = len(matches) - count

    # Now that we have our searches to check, run them
    search_hits = 0
    search_misses = 0
    for search_id, search_fields in matches.items():
        if find_matches(event, search_fields, match_all):
            search_hits += 1
        else:
            search_misses += 1

        # Short circuit if we found the matches, or if we can't find the number anymore

        if search_hits >= count:
            return True

        if search_misses > permitted_misses:
            return False

    return False
