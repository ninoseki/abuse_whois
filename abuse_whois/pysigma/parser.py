"""
This parser uses lark to transform the condition strings from signatures into callbacks that
invoke the right sequence of searches into the rule and logic operations.
"""
from typing import Any

from lark import Lark, Token, Transformer, Tree

from . import schemas
from .exceptions import UnsupportedFeature
from .sigma_scan import analyze_x_of, match_search_id

# Grammar defined for the condition strings within the Sigma rules
grammar = """
        start: pipe_rule
        %import common.WORD   // imports from terminal library
        %ignore " "           // Disregard spaces in text
        pipe_rule: or_rule ["|" aggregation_expression]
        or_rule: and_rule (("or"|"OR") and_rule)*
        and_rule: not_rule (("and"|"AND") not_rule)*
        not_rule: [not] atom
        not: "NOT" | "not"
        atom: x_of | search_id | "(" pipe_rule ")"
        search_id: SEARCH_ID
        x: ALL | NUMBER
        x_of: x OF search_pattern
        search_pattern: /[a-zA-Z*_][a-zA-Z0-9*_]*/
        aggregation_expression: aggregation_function "(" [aggregation_field] ")" [ "by" group_field ] comparison_op value
                              | near_aggregation
        aggregation_function: COUNT | MIN | MAX | AVG | SUM
        near_aggregation: "near" or_rule
        aggregation_field: SEARCH_ID
        group_field: SEARCH_ID
        comparison_op: GT | LT | EQ
        GT: ">"
        LT: "<"
        EQ: "="
        value: NUMBER
        NUMBER: /[1-9][0-9]*/
        NOT: "NOT"
        SEARCH_ID: /[a-zA-Z_][a-zA-Z0-9_]*/
        ALL: "all"
        OF: "of"
        COUNT: "count"
        MIN: "min"
        MAX: "max"
        AVG: "avg"
        SUM: "sum"
        """


def check_event(event: dict[Any, Any], rule: schemas.Rule):
    alerts: list[schemas.Alert] = []

    condition = rule.get_condition()
    if condition is None:
        return alerts

    if condition(rule, event):
        alert = schemas.Alert(event=event, rule=rule)
        alerts.append(alert)

    return alerts


class FactoryTransformer(Transformer):
    @staticmethod
    def start(args):
        return args[0]

    @staticmethod
    def search_id(args: list[Token]):
        name = args[0].value

        def match_hits(signature, event):
            return match_search_id(signature, event, name)

        return match_hits

    @staticmethod
    def search_pattern(args: list[Token]):
        return args[0].value

    @staticmethod
    def atom(args: list):
        if not all(callable(_x) for _x in args):
            raise ValueError(args)

        return args[0]

    @staticmethod
    def not_rule(args):
        negate, value = args

        assert callable(value)

        if negate is None:
            return value

        def _negate(*state):
            return not value(*state)

        return _negate

    @staticmethod
    def and_rule(args):
        if not all(callable(_x) for _x in args):
            raise ValueError(args)

        if len(args) == 1:
            return args[0]

        def _and_operation(*state):
            for component in args:
                if not component(*state):
                    return False

            return True

        return _and_operation

    @staticmethod
    def or_rule(args):
        if not all(callable(_x) for _x in args):
            raise ValueError(args)

        if len(args) == 1:
            return args[0]

        def _or_operation(*state):
            for component in args:
                if component(*state):
                    return True

            return False

        return _or_operation

    @staticmethod
    def pipe_rule(args):
        return args[0]

    @staticmethod
    def x_of(args):
        # Load the left side of the X of statement
        count = None
        if args[0].children[0].type == "NUMBER":
            count = int(args[0].children[0].value)

        # Load the right side of the X of statement
        selector = str(args[2])
        if selector == "them":
            selector = None

        # Create a closure on our
        def _check_of_sections(signature, event):
            return analyze_x_of(signature, event, count, selector)

        return _check_of_sections

    @staticmethod
    def aggregation_expression(args):
        raise UnsupportedFeature("Aggregation expressions not supported.")

    @staticmethod
    def near_aggregation(args):
        raise UnsupportedFeature("Near operation not supported.")


# Create & initialize Lark class instance
factory_parser = Lark(
    grammar, parser="lalr", transformer=FactoryTransformer(), maybe_placeholders=True
)


def prepare_condition(raw_condition: str | list) -> Tree:
    if isinstance(raw_condition, list):
        raw_condition = "(" + ") or (".join(raw_condition) + ")"

    return factory_parser.parse(raw_condition)
